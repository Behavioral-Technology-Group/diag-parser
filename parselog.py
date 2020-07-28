#!/usr/bin/env python3
'''Extract data from diagnostic log'''

import base64
from binascii import hexlify
import datetime as dt
import itertools
import json
import logging
from pathlib import Path
import re
import struct
import sys
import time


version = '1.1.0'

log = logging.getLogger()


# # so we can run programmatically from bopeep
# class args:
#     json = False
#     filter = None


class AppError(Exception):
    '''Base class for custom exceptions.'''

class HttpError(AppError):
    '''HTTP error'''

class ParseError(AppError):
    '''Error during data parsing'''

class OutOfData(AppError):
    '''Ran out of data.'''

since2017 = dt.datetime.now() - dt.datetime(2017,1,1)


def hexlify(x, spaced=False, _hex=hexlify):
    res = _hex(x).decode()
    if spaced:
        return ' '.join(re.findall('..', res))
    else:
        return res


def extract(names, d):
    return {k: d[k] for k in names.split()}



def decode_duration(x):
    '''Decode a special one-byte duration field that stores a value
    with a variable compression technique that allows a large dynamic
    range without sacrificing resolution for small values.  This
    particular algorithm can encode values from 0 to 10999 in only
    six bits (and ignores the upper two bits of the byte!).'''
    if x > 0b00111110:  # TODO: legacy value? Maybe can remove now.
        return 500
    scale = (x >> 4) & 0b11
    mult = x & 0b1111
    if scale == 0b00:
        return 0 + mult * 10
    elif scale == 0b01:
        return 200 + mult * 50
    elif scale == 0b10:
        return 1000 + mult * 100
    elif scale == 0b11:
        return 3000 + mult * 500



class Record:
    '''Base class for all records.  Subclasses should be defined with
    an "rtype" field matching the record's type value from logging.h
    in the firmware source.  For example, LREC_ZAP is record type 4 so
    the ZapRecord class specifies rtype = 4.'''


    @classmethod
    def _reset(cls):
        Record._ts_base = dt.datetime(1999,1,1) # + dt.timedelta(seconds=1552474341)
        cls._tocks = 0
        cls._prev_rec = cls._rec = None


    @classmethod
    def get_class(cls, rtype):
        '''Retrieve Record subclass with specified rtype.'''
        try:
            try:
                cmap = cls._class_map
            except AttributeError:
                # build map from available subclasses
                cmap = cls._class_map = {
                    s.rtype: s
                        for s in cls.__subclasses__()
                            if hasattr(s, 'rtype')
                    }

            return cmap[rtype]

        except KeyError:
            return UnknownRecord


    debug = False

    def __init__(self, code, src):
        Record._prev_rec = Record._rec
        Record._rec = self

        self.type = code
        self.raw = bytearray([self.type])

        try:
            self.name = self._name  # optional, feature not used yet
        except AttributeError:
            name = self.__class__.__name__
            if name == 'Record':
                name = '?'
            elif name.endswith('Record'):
                name = name[:-len('Record')]
            self.name = name

        try:
            self._parse(code, src)  # to allow subclasses to change
        # except struct.error as ex:
        #     print('%s: code=%s source=%r' % (ex, code, src[:50]))
        except Exception as ex:
            raise ParseError('%s: error parsing: %s' % (self.name, hexlify(self.raw, spaced=True)))


    def _parse(self, code, src):
        try:
            byte = src.pop(0)
        except IndexError:
            raise OutOfData
        self.raw.append(byte)
        self.length = byte & 0x7f
        self.timestamped = bool(byte & 0x80)
        if self.timestamped:
            try:
                self._tocks = struct.unpack_from('<H', src)[0]
            except struct.error:
                raise OutOfData
            self.raw.extend(src[:2])
            del src[:2]
            Record._tocks += self._tocks

            self._ts = Record._ts_base + dt.timedelta(seconds=Record._tocks / 64)

        self.data = bytearray(src[:self.length])

        del src[:self.length]
        self.raw.extend(self.data)

        self.fields = dict(
            type=self.rtype,
            data=self.data.hex(),
            raw=self.raw.hex(),
            len=self.length,
            timestamped=self.timestamped,
            name=self.name,
            )

        f = self.parse()
        self.fields['v'] = f

        try:
            self.fields['ts'] = self._ts.strftime('%Y-%m-%d %H:%M:%S') + ('.%03d' % (self._ts.microsecond / 1000))
        except AttributeError:
            self.fields['ts'] = ''


    def parse(self):
        return {}


    def get_meta(self):
        '''Retrieve a dictionary of fields common to all Records.'''

        return self.fields


    def text_header(self):
        f = self.fields
        return f'{f["ts"] or "-":^23} {f["type"]:3} {f["name"]:>12}'


    def text_body(self):
        '''Override in subclasses unless they pre-generate self._text'''
        try:
            return self._text
        except AttributeError:
            return hexlify(self.data, spaced=True).upper()


    def __str__(self):
        r = [self.text_header(), self.text_body()]
        if self.debug:
            r.append(' ' + hexlify(self.raw))
        return ' '.join(r)



class ErasedRecord(Record):
    rtype = 0   # LREC_ERASED



class TimestampRecord(Record):
    rtype = 1   # LREC_TIMESTAMP

    def parse(self):
        value = struct.unpack_from('<L', self.data)[0]
        self._ts = dt.datetime.fromtimestamp(value)
        # if self._ts < dt.datetime(2018, 1, 1, 0, 0):
        #     later = max(Record._ts + dt.timedelta(seconds=Record._tocks / 64),
        #         CatRecord._cat7_ts + dt.timedelta(minutes=1) * CatRecord._count)
        #     self._ts = later + dt.timedelta(seconds=5)
        Record._tocks = 0
        Record._ts_base = self._ts

        self._value = value

        return dict(
            offset=None,
            )


    def add_repr(self, r):
        r.append(' 0x%x' % self._value)



class RebootRecord(Record):
    rtype = 2   # LREC_REBOOT

    REASONS = {
        (1 << 0): 'hard-reset',
        (1 << 1): 'watchdog',
        (1 << 2): 'soft-reset',
        (1 << 3): 'lockup',
        (1 << 4): 'bit4',
        (1 << 5): 'bit5',
        (1 << 6): 'hibernate',  # RESET_SYSTEM_OFF_MODE in main.c
    }

    def parse(self):
        code = self.data[0]
        if code == (1 << 7):    # RESET_SHUTDOWN_BIT in main.c
            reason = 'shutdown'
            rtext = ''
            self.fields['name'] = 'Shutdown'
        elif code:
            reason = ','.join(self.REASONS[bit] for bit in self.REASONS if code&bit)
            rtext = f'reason={reason} '
        else:
            reason = 'power'
            rtext = 'reason=power '

        if len(self.data) >= 3:
            version = '5.%d.%d' % tuple(self.data[1:3])
        else:
            version = None
        ver = f' ver={version}' if version else ''

        self._text = f'{rtext}code={code}{ver}'

        return dict(
            code=code,
            reason=reason,
            version=version,
            )



class ButtonRecord(Record):
    rtype = 3   # LREC_BUTTON

    ACTIONS = {
        1: 'quick',
        2: 'q-s',
        3: 'short',
        4: 's-l',
        5: 'long',
        6: 'l-vl',
        7: 'verylong',
    }

    def parse(self):
        b0, b1 = struct.unpack_from('BB', self.data)
        try:
            action = self.ACTIONS[b0]
        except KeyError:
            action = f'h{b0:02x}'

        if b1 < 150:
            duration = b1 * 10
        elif b1 < 255:
            duration = (b1 - 150) * 100 + 1500
        else:
            duration = 12000

        self._text = f'action={action} dur={duration}ms'

        return dict(
            action=action,
            duration=duration,
            )



class ZapRecord(Record):
    rtype = 4   # LREC_ZAP

    def parse(self):
        if len(self.data) > 1:
            names = []
            if len(self.data) >= 9:
                b0, b1, b2, b3, b4, b5, b6, b7, b8 = struct.unpack_from('BBBBBBBBB', self.data)
                t10 = b6 * 4
                minv = b7 * 2
                maxv = b8 * 2
                extra = f' t10={t10:3}ms min={minv:3}V max={maxv:3}V'
                extras = dict(t10=t10, minv=minv, maxv=maxv)
            else:
                b0, b1, b2, b3, b4, b5 = struct.unpack_from('BBBBBB', self.data)
                extra = ''
                extras = {}

            target = (b0 & 0xf) * 10
            charged = bool(b0 & 0x10)
            skipped = bool(b0 & 0x20)
            battv = round((b1 * 4 + 3180) / 1000.0, 3)
            release = b2 * 2
            exit = b3 * 2
            tchg = b4 * 4
            trel = b5 * 4
            if charged:
                chgtext = f'{tchg:3}ms'
            else:
                chgtext = '(NOT)'
                tchg = 0
            self._text = (
                f'{target:3}% chg={chgtext} r={release:3}V'
                f' rel={trel:3}ms{extra} x={exit:3}V{"SKIP" if skipped else ""}'
                f' @{battv:.3}V'
                )

            results = extract('target charged skipped battv release exit tchg trel', locals())
            results.update(extras)
            return results

        else:
            code = struct.unpack_from('B', self.data)[0]
            reason = {
                0: 'ZAP_OKAY',
                1: 'ZERO_PARAM',
                2: 'CHARGING',
                3: 'EXCESS',
                4: 'HV_CHECK',
                5: 'LOW_BATT',
                6: 'BUTTON',
            }.get(code, '(unknown code)')
            self._text = 'skipped (%s)' % (reason)

            return dict(
                skip=True,
                reason=reason,
                )

    # def add_repr(self, r):
    #     r.append(' %3d%% chg=%3dms r=%3dV rel=%3dms x=%3dV%s @%.3fV' % (
    #         self.target,
    #         self.tchg,
    #         self.release,
    #         self.trel,
    #         self.exit,
    #         ' SKIP' if self.skipped else '',
    #         self.battv))



class ConnectRecord(Record):
    rtype = 5   # LREC_CONNECT

    def parse(self):
        mac, ci = struct.unpack_from('<6sH', self.data)
        mac = ':'.join('%02X' % x for x in bytearray(mac))

        self._text = f'mac={mac} ci={ci}ms'

        return dict(
            mac=mac,
            ci=ci,
            )



class DisconnectRecord(Record):
    rtype = 6   # LREC_DISCONNECT



class TimeDeltaRecord(Record):
    rtype = 7   # LREC_TIME_DELTA

    def parse(self):
        delta = struct.unpack_from('<l', self.data)[0]
        if delta > since2017.total_seconds():
            # dtext = f'({delta/365.25:.0f} days: RTC was reset)'
            dtext = f'({dt.timedelta(seconds=delta)}: RTC was reset)'
        elif delta > 90:
            text = str(dt.timedelta(seconds=delta))
            dtext = f'{text} ({delta:+}s)'
        else:
            dtext = f'{delta:+}s'

        self._text = f'delta={dtext}'

        return dict(delta=delta)



class BatteryRecord(Record):
    rtype = 8   # LREC_BATTERY

    def parse(self):
        voltage = struct.unpack_from('<H', self.data)[0]
        vusb = bool(voltage & 0x8000)
        if vusb and bool(voltage & 0x4000):
            charged = True
            vusb = False
        else:
            charged = False
        voltage = round((voltage & 0x3fff) / 1000.0, 3)

        ct = ' CHG' if charged else ''
        vt = ' VUSB' if vusb else ''
        self._text = f'{voltage:.3f}V{ct}{vt}'

        return dict(
            voltage=voltage,
            vusb=vusb,
            charged=charged,
            )



class ReconnectRecord(Record):
    rtype = 9   # LREC_RECONNECT



class CatRecord(Record):
    '''A mostly no longer used record for Continuous Activity Tracking.'''

    rtype = 10   # LREC_CAT

    def parse(self):
        level, = struct.unpack_from('<H', self.data)
        fast = bool(level & 0x8000)
        level &= 0x7fff

        self._text = f'level={level:5} ({"active" if fast else "idle"})'

        return dict(
            level=level,
            active=fast,
            )



class SleepRecord(Record):
    rtype = 11  # LREC_SLEEP

    REASON = {
        0: 'no-op',
        1: 'store',
        2: 'replace',
        3: 'merge',
        4: 'too short',
        5: 'too long',
    }

    def parse(self):
        flags, = struct.unpack_from('<B', self.data)

        ftext = ''.join([
            'd' if flags&1 else '-',
            'u' if flags&2 else '-',
            'S' if flags&4 else '-',
            'i' if flags&8 else '-',
            ])
        code = flags >> 4   # high nybble is reason for ending sleep

        res = dict(flags=ftext, code=code)

        if len(self.data) <= 2:
            self._text = ftext
        else:
            count, duration, end = struct.unpack_from('<BHL', self.data, offset=1)
            end = dt.datetime.fromtimestamp(end)
            duration = dt.timedelta(seconds=duration)
            begin = end - duration
            # append(' #%d %s-%s (%s) -> %s' % (
            #     count,
            #     begin.strftime('%H:%M:%S'),
            #     end.strftime('%H:%M:%S'),
            #     duration,
            #     self.REASON.get(code, '%s?' % code)
            #     ))

            reason = self.REASON.get(code, f'{code}?')
            self._text = (f'{ftext} #{count}'
                f' {begin.strftime("%H:%M:%S")}-{end.strftime("%H:%M:%S")} ({duration})'
                f' -> {reason}'
                )

            res.update(dict(
                count=count,
                begin=str(begin),
                end=str(end),
                dur_s=int(duration.total_seconds()),
                duration=str(duration),
                reason=reason,
                ))

        return res



class BluetoothRecord(Record):
    rtype = 12  # LREC_BLUETOOTH

    def parse(self):
        try:
            hext = self.data[1:].hex()
        except AttributeError:
            hext = hexlify(self.data[1:])
        self._text = 'h=%d %s' % (self.data[0], hext)

        return dict(
            handle=self.data[0],
            payload=hext,
            )



class SleepStartRecord(Record):
    rtype = 13  # LREC_SLEEP_START

    # Removed in 5.6.60


class SleepEndRecord(Record):
    rtype = 14  # LREC_SLEEP_END

    # Removed in 5.6.60

    def add_repr(self, r):
        r.append(' reason=%d' % struct.unpack_from('B', self.data)[0])



class AlarmLoadRecord(Record):
    rtype = 15  # LREC_ALARM_LOAD

    def parse(self):
        if len(self.data) >= 4:
            delta, aid = struct.unpack_from('<HH', self.data)
        else:
            delta, = struct.unpack_from('<H', self.data)
            aid = 0

        delta *= 10
        dtime = dt.timedelta(seconds=delta)
        alarm_time = dt.datetime.fromtimestamp(round((self._ts + dtime).timestamp() / 60) * 60)

        self._text = f'#{aid} delta={dtime} (at ~{alarm_time})'

        return dict(
            aid=aid,
            delta=delta,
            alarm_time=str(alarm_time),
            )



class AlarmTriggerRecord(Record):
    rtype = 16  # LREC_ALARM_TRIGGER

    def parse(self):
        # breakpoint()
        if len(self.data) >= 8:
            fields = struct.unpack_from('<BBBBBBH', self.data)
            aid = fields[-1]
            fields = fields[:-1]
        else:
            fields = struct.unpack_from('BBBBBB', self.data)
            aid = 0
        ctrl = fields[0]
        snooze = fields[1]
        pretrigger = bool(fields[2] & 0x80)
        pre_delay = (fields[2] & 0x7f) * 2 * 10
        duration = fields[4] * 60
        interval = fields[5] * 5

        pre = f' pre={pre_delay}s' if pretrigger else ''
        self._text = (
            f'#{aid} c={ctrl} sn={snooze}{pre}'
            f' d={duration}s i={interval}s'
            )

        return extract('aid ctrl snooze pretrigger pre_delay duration interval', locals())



class AlarmSnoozeRecord(Record):
    rtype = 17  # LREC_ALARM_SNOOZE


class AlarmEndRecord(Record):
    rtype = 18  # LREC_ALARM_END


class HdActiveRecord(Record):
    rtype = 19  # LREC_HD_ACTIVE


class HdInactiveRecord(Record):
    rtype = 20  # LREC_HD_INACTIVE


class DoubletapRecord(Record):
    rtype = 21  # LREC_DOUBLETAP


class FileDumpRecord(Record):
    rtype = 22  # LREC_FILE_DUMP

    def parse(self):
        ftype, flen = struct.unpack_from('<BL', self.data)
        self._text = f't={ftype} n={flen}'
        return extract('ftype flen', locals())



class ConfigRecord(Record):
    rtype = 23  # LREC_CONFIG

    ANGLES = [
        22.1,   # default when 0, becomes 6+1 or 22.1 degrees
        5.0, # 498,    //  +/- 5.0 degrees off-centre
        7.9, # 1225,   //  +/- 7.9 degrees off-centre
        10.7, # 2265,   // +/- 10.7 degrees off-centre
        13.6, # 3609,   // +/- 13.6 degrees off-centre
        16.4, # 5242,   // +/- 16.4 degrees off-centre
        19.3, # 7149,   // +/- 19.3 degrees off-centre
        22.1, # 9310,   // +/- 22.1 degrees off-centre
        25.0, # 11705,  // +/- 25.0 degrees off-centre
        27.9, # 14309,  // +/- 27.9 degrees off-centre
        30.7, # 17097,  // +/- 30.7 degrees off-centre
        33.6, # 20040,  // +/- 33.6 degrees off-centre
        36.4, # 23109,  // +/- 36.4 degrees off-centre
        39.3, # 26275,  // +/- 39.3 degrees off-centre
        42.1, # 29505,  // +/- 42.1 degrees off-centre
        45.0, # 32768,  // +/- 45.0 degrees off-centre
        ]

    def parse(self):
        # 17 09 03 17 00 01 0A 01 0A 03 00
        (button, hd_ctrl, hd_select, motor_cnt, motor_level,
            piezo_cnt, piezo_level, zap_cnt, zap_level) = struct.unpack_from('9B', self.data)

        button = {0: 'invalid', 1: 'vibe', 2: 'beep', 3: 'zap'}.get(button, '?')

        dtap = 'on' if (hd_ctrl & (1 << 1)) else 'off'
        if hd_ctrl & (1 << 0):
            orient = f'{"front" if hd_ctrl & (1 << 3) else "back"} {"left" if hd_ctrl & (1 << 4) else "right"}'
            angle = self.ANGLES[hd_select >> 4]
            # hd_ctrl = f'{orient} (dtap={dtap})'
            hd_ctrl = f'{orient}'
            hd_select = f'{angle:.0f}° cone'
            hd = f'{hd_ctrl}, {hd_select}'
        else:
            hd_ctrl = hd = 'off'
            hd_select = ''

        self._text = (
            f'button={button} hd={hd} dtap={dtap}'
            f' mot={motor_cnt}@{motor_level}'
            f' pzo={piezo_cnt}@{piezo_level}'
            f' zap={zap_cnt}@{zap_level}'
            )

        return extract('button dtap hd_ctrl hd_select motor_cnt motor_level'
                ' piezo_cnt piezo_level zap_cnt zap_level',
                locals())



class DaqStartRecord(Record):
    rtype = 24  # LREC_DAQ_START

    # Removed in 5.6.60



class JumpingJackRecord(Record):
    rtype = 25  # LREC_JJ

    def parse(self):
        # 00 7C10 2708 CCF6 8514 AF31 94F3 0A00 FC03 EC00
        fields = struct.unpack_from('<B3hhHhHHH', self.data)
        (self.valid, self.x, self.y, self.z,
            self.x_mean, self.y_span, self.z_mean,
            self.count, self.period, self.cycles,
            ) = fields

    def add_repr(self, r):
        r.append(' %s %5d,%5d,%5d xm=%d ys=%5u zm=%5d i=%2u T=%4d n=%d' % (
            '1' if self.valid else '0',
            self.x, self.y, self.z,
            self.x_mean, self.y_span, self.z_mean,
            self.count, self.period, self.cycles,
            ))



class VibeRecord(Record):
    rtype = 26  # LREC_VIBE

    def parse(self):
        skip = bool(len(self.data) == 1)
        if skip:
            code, = struct.unpack_from('B', self.data)
            reason = {
                0: 'VIBE_OKAY',
                1: 'ZERO_PARAM',
                5: 'LOW_BATT',
                6: 'BUTTON',
            }.get(code, '(unknown code)')

            self._text = f'skipped ({reason})'

            return extract('skip code reason', locals())

        else:
            count, level, freq, duration = struct.unpack_from('<4B', self.data)
            freq *= 500     # is this correct? Compare BeepRecord
            dur = decode_duration(duration)
            # FIXME: should something here be divided by 1000?
            durtext = f'{dur:.1f}s' if dur >= 1000 else f'{dur}ms'

            self._text = f'n={count} at {level}% f={freq}Hz for {durtext}'

            return dict(
                count=count,
                level=level,
                freq=freq,
                duration=dur,
                )



class BeepRecord(Record):
    rtype = 27  # LREC_BEEP

    def parse(self):
        skip = bool(len(self.data) == 1)
        if skip:
            code = struct.unpack_from('B', self.data)[0]
            reason = {
                0: 'VIBE_OKAY',
                1: 'ZERO_PARAM',
                5: 'LOW_BATT',
                6: 'BUTTON',
            }.get(code, 'unknown')
            self._text = f'skipped ({reason})'

            return extract('skip code reason', locals())

        else:
            count, freq, duration = struct.unpack_from('<3B', self.data)
            freq = (freq // 10 - 1) * 800 + 200 # compare with VibeRecord

            dur = decode_duration(duration)
            # FIXME: should something here be divided by 1000?
            durtext = f'{dur:.1f}s' if dur >= 1000 else f'{dur}ms'

            self._text = f'n={count} at f={freq}Hz for {durtext}'

            return dict(
                count=count,
                freq=freq,
                duration=dur,
                )



class BluetoothErrorRecord(Record):
    rtype = 28  # LREC_BLE_ERROR

    # Probably not used in any recent firmware



class StepsRecord(Record):
    rtype = 29  # LREC_STEPS

    def parse(self):
        # clone EnergyRecord's timestamp if it was immediately before us
        # (as should almost always be the case)
        if isinstance(Record._prev_rec, EnergyRecord):
            self._ts = Record._prev_rec._ts

        count, rate = struct.unpack_from('<HB', self.data)
        if rate < 255:
            rate = (rate * 2) / 100.0
            rtext = f'{rate:.2f}'
        elif count:
            rtext = rate = 'undefined'
        else:
            rate = 0

        self._text = f'rate={rtext} n={count}'

        return dict(
            count=count,
            rate=rate,
            )



class EnergyRecord(Record):
    rtype = 30  # LREC_ENERGY

    def parse(self):
        if len(self.data) == 6:
            mean, level, maxlev = struct.unpack_from('<HHH', self.data)
            self._text = 'mean=%s level=%s max=%s' % (mean, level, maxlev)

            return dict(
                mean=mean,
                level=level,
                maxlev=maxlev,
                )
        else:
            try:
                self._text = self.data[1:].hex()
            except AttributeError:
                self._text = hexlify(self.data[1:])

            return {}



class FflagsRecord(Record):
    rtype = 31  # LREC_FFLAGS

    def parse(self):
        if len(self.data) == 4:
            flags, = struct.unpack_from('<L', self.data)
            amazon = bool(flags & 0x01)
            variant = (flags >> 1) & 0x7f
            # e.g. STC is 1 etc

            self._text = f'{flags:08x} {"Amazon" if amazon else ""}'
        else:
            try:
                self._text = self.data[1:].hex()
            except AttributeError:
                self._text = hexlify(self.data[1:])

        return dict(
            flags=flags,
            amazon=amazon,
            variant=variant,
            )


class UflagsRecord(Record):
    rtype = 38  # LREC_UFLAGS

    def parse(self):
        if len(self.data) == 4:
            flags, = struct.unpack_from('<L', self.data)
            locked = bool(flags & 0x01)

            self._text = f'{flags:08x} {"LOCKED" if locked else ""}'
        else:
            try:
                self._text = self.data[1:].hex()
            except AttributeError:
                self._text = hexlify(self.data[1:])

        return dict(
            flags=flags,
            locked=locked,
            )


class HflagsRecord(Record):
    rtype = 39  # LREC_HFLAGS

    def parse(self):
        if len(self.data) == 4:
            flags, = struct.unpack_from('<L', self.data)
            pav3 = bool(flags & 0x01)

            self._text = f'{flags:08x} {"PAV3" if pav3 else ""}'
        else:
            try:
                self._text = self.data[1:].hex()
            except AttributeError:
                self._text = hexlify(self.data[1:])

        return dict(
            flags=flags,
            pav3=pav3,
            )



class AncsRecord(Record):
    rtype = 34  # LREC_ANCS
    # Event:
    # 11:53:16.328 (32) 28 00 01 00 08 00 00 10 09 01 00 00 00 00
    #
    # Event (Notification) Attributes, spread over multiple notifies:
    # 11:53:16.375 (32) 2B 00 01 00 14 00   00 00 00 00 00 00 16 00 63 6F 6D 2E 74 69 6E 79 73 70 65 63
    #   -> b'\x16\x00com.tinyspec'
    # 11:53:16.375 (32) 2B 00 01 00 14 00   6B 2E 63 68 61 74 6C 79 69 6F 01 05 00 53 6C 61 63 6B 02 00
    #   -> b'k.chatlyio\x01\x05\x00Slack\x02\x00'
    # 11:53:16.390 (32) 2B 00 01 00 14 00   00 03 14 00 40 50 65 74 65 72 20 48 61 6E 73 65 6E 3A 20 70
    #   -> b'\x00\x03\x14\x00@Peter Hansen: p'
    # 11:53:16.390 (32) 2B 00 01 00 14 00   69 6F 6E 67 04 02 00 32 30 05 0F 00 32 30 32 30 30 36 31 37
    #   -> b'iong\x04\x02\x0020\x05\x0f\x0020200617'
    # 11:53:16.390 (32) 2B 00 01 00 12 00   54 31 31 35 33 31 34 06 00 00 07 05 00 43 6C 65 61 72
    #   -> b'T115314\x06\x00\x00\x07\x05\x00Clear'
    #
    # App attributes:
    # 11:53:16.562 (32) 2B 00 01 00 14 00   01 63 6F 6D 2E 74 69 6E 79 73 70 65 63 6B 2E 63 68 61 74 6C
    #   -> b'\x01com.tinyspeck.chatl'
    # 11:53:16.562 (32) 2B 00 01 00 0C 00   79 69 6F 00 00 05 00 53 6C 61 63 6B
    #   -> b'yio\x00\x00\x05\x00Slack'
    # So handle is first uint16_t.  0x28 is the event, 0x2B are the attribute data.

    EIDS = {
        0: 'added',
        1: 'modified',
        2: 'removed',
    }

    CATS = {
        0: 'other',
        1: 'call',
        2: 'missed call',
        3: 'voicemail',
        4: 'social',
        5: 'schedule',
        6: 'email',
        7: 'news',
        8: 'health-fitness',
        9: 'biz-finance',
        10: 'location',
        11: 'entertainment',
    }

    FLAGS = {
        0x01: 'silent',
        0x02: 'important',
        0x04: 'pre-existing',
        0x08: 'pos-action',
        0x10: 'neg-action',
    }

    def parse(self):
        if len(self.data) >= 1:
            dat = {}
            typ, = struct.unpack_from('<B', self.data)

            if typ == 0:
                ttext = 'event'
                fields = struct.unpack_from('<BBBBL', self.data[1:])
                eid = self.EIDS.get(fields[0], '?')
                flags = '/'.join(v for k, v in self.FLAGS.items() if fields[1] & k)
                catid = self.CATS.get(fields[2], '?')
                ccnt = fields[3]
                nuid = fields[4]
                dat = dict(
                    eid=fields[0],
                    flags=fields[1],
                    catid=catid,
                    ccnt=ccnt,
                    nuid=nuid,
                    )
                etext = f'{eid}, flags={flags}, cat={catid} n={ccnt}, uid={nuid}'
                # self._text = f'{ttext}: hnd=0x{hnd:x} {etext}'
                self._text = f'{ttext}: {etext}'

            elif typ == 1:
                ttext = 'attr'
                etext = repr(bytes(self.data[1:]))
                # self._text = f'{ttext}: hnd=0x{hnd:x} {etext}'
                self._text = f'{ttext}: {etext}'

            else:
                ttext = f'{typ}'
                dat = dict(type=ttext, text=repr(bytes(self.data[1:])))

                self._text = f'{ttext}: {bytes(self.data[1:])}'

            return dat or dict(
                type=ttext,
                text=etext,
                )
        else:
            ttext = 'error'
            try:
                self._text = self.data[1:].hex()
            except AttributeError:
                self._text = hexlify(self.data[1:])

            return dict(
                type=ttext,
                text=self._text,
                )


class CrashRecord(Record):
    rtype = 36  # LREC_CRASH

    def parse(self):
        if len(self.data) == 12:
            fault_id, pc, error = struct.unpack_from('<LLL', self.data)

            self._text = f'fault={fault_id:08x} pc={pc:08x} error={error:08x}'
        else:
            try:
                self._text = self.data[1:].hex()
            except AttributeError:
                self._text = hexlify(self.data[1:])

        return extract('fault_id pc error', locals())



class OtaRecord(Record):
    rtype = 37  # LREC_OTA

    CODES = {
        0xC0: 'unlock',
        0xC1: 'lock',
        0xC2: 'fflags',
        0xC3: 'hflags',
        0xC4: 'uflags',
        0xCB: 'blink',
        0xCC: 'crash',
        0xCD: 'reset',
        0xCE: 'wipe',
        0xCF: 'hibernate',
    }

    def parse(self):
        if len(self.data) == 1:
            code, = struct.unpack_from('<B', self.data)

            name = self.CODES.get(code, '?')

            self._text = f'code={code:02X} ({name})'
        else:
            try:
                self._text = self.data[1:].hex()
            except AttributeError:
                self._text = hexlify(self.data[1:])

        return extract('code name', locals())



class UnusedRecord(Record):
    '''Not a true record... just covers unused bytes at end of a sector.'''

    ERASED_BYTE = rtype = 0xFF

    def __init__(self, code, src):
        # We're not a real record, so don't disrupt things by assuming
        # the role of "previous record".  Basically save the value,
        # let base class initialize, then restore the value so the next
        # record will see the previous real record rather than us.
        self._true_prev_rec = Record._rec
        super().__init__(code, src)
        Record._rec = self._true_prev_rec


    def _parse(self, code, src):
        while True:
            byte = src.pop(0)
            if byte != self.ERASED_BYTE:
                src.insert(0, byte)
                break

            self.raw.append(byte)

        self.timestamped = False
        self.data = bytearray()
        self.length = len(self.raw)

        self.fields = dict(
            raw=self.raw.hex(),
            type=self.rtype,
            data=self.data.hex(),
            len=self.length,
            timestamped=self.timestamped,
            name=self.name,
            ts='',
            v={},
            )

        n = len(self.raw)
        s = '' if n==1 else 's'
        self._text = f'({n} erased byte{s} at end of sector)'



class UnknownRecord(Record):
    '''Handles all records that aren't handled specifically by other classes.'''

    # no need to specify an rtype value here

    def __init__(self, rtype, *args, **kwargs):
        self.rtype = rtype
        self._name = f'Unknown({rtype})'
        super().__init__(rtype, *args, **kwargs)




class LogParser:
    def __init__(self):
        pass


    def get_feedback(self):
        '''Get "feedback" data from the MVP server.'''
        url = args.host + args.query.format(**args.__dict__)

        import requests
        res = requests.get(url)
        res.encoding = 'utf-8'
        msg = f'HTTP response {res.status_code}: {res.reason}'
        if not res:
            log.error(msg)
            raise HttpError(msg)

        res_raw = res.text
        res_repr = repr(res_raw)
        N = 60
        res_short = res_repr if len(res_repr) <= N else res_repr[:N-10] + ' ... ' + res_repr[-10:]
        log.debug('response begins with %s', res_short)

        try:
            data = json.loads(res_raw)
            log_b64 = data['raw_input']['diagnostic_data']
            if len(log_b64) < 8:    # arbitrary limit... real data always longer
                raise ParseError('diagnostic data too short')

            log_raw = base64.b64decode(log_b64)

        except ValueError:  # from key lookup on non-dict
            raise ParseError('JSON not an object: %s' + res_short)

        except KeyError:    # from key not found
            raise ParseError('raw_input.diagnostic_data not found')

        except json.JSONDecodeError:    # from non-JSON content
            raise ParseError(f'data ({len(res_raw)} bytes) is not JSON')

        return log_raw


    def retrieve(self):
        '''Retrieve feedback data from web or filesystem.'''
        path = Path(args.fid)
        if path.exists():
            data = path.read_bytes()

            # try treating as extracted encoded data
            try:
                m = re.search(r'diagnostic_data"=>"(.*)"', data)
                data = m.group(1).replace(r'\n', '\n')
                data = base64.b64decode(data)
            except TypeError:   # probably binary data, so already decoded
                pass

        else:   # retrieve from web
            data = self.get_feedback()

            # optionally cache it locally
            if args.cache:
                Path(args.fid).write_bytes(data)

        return data


    def get_record(self, f):
        '''Parse next record from the source data.'''
        try:
            rtype = f.pop(0)
        except IndexError:
            raise OutOfData from None

        cls = Record.get_class(rtype)
        return cls(rtype, f)


    def parse(self, data):
        Record._reset()
        CatRecord._reset()

        src = bytearray(data)
        num_bytes = len(src)
        log.debug('raw data size %d (%d erased)', num_bytes, len(data) - num_bytes)

        count = 0
        while True:
            try:
                rec = self.get_record(src)
            except OutOfData:
                break
            except ParseError as ex:
                log.exception('this sucks: %s', ex)
                # print(ex)
                raise

            count += 1
            yield rec


    def output_text(self, records):
        try:
            log.debug('parsing records')
            for rec in records:
                print(rec)

        except TypeError:
            log.error('failure in: %s', ' '.join(re.findall('..', hexlify(rec.raw))))
            raise


    def output_json(self, records):
        data = {
            'cwd': str(Path.cwd()),
            'generator': str(Path(__file__)),
            'version': version,
            'date': str(dt.datetime.now()),
        }

        entries = data['log'] = []

        log.debug('parsing records')
        raw_len = 0
        for i, rec in enumerate(records):
            j = rec.fields
            log.debug('rec: %s', j)
            json.dumps(j)   # just to test so errors are reported sooner
            entries.append(j)
            raw_len += len(rec.raw)

        data['bytes'] = raw_len
        data['count'] = i

        opts = dict(indent=4) if args.pretty else dict(separators=(',',':'))
        print(json.dumps(data, **opts))


    def run(self):
        if args.json:
            output = self.output_json
        else:
            output = self.output_text
        # try:
        #     output = getattr(self, 'output_' + args.mode)
        # except AttributeError:
        #     raise AppError(f'invalid output mode: {args.mode}')

        log.debug('-' * 60)
        log.info(f'parselog v{version}')

        raw = self.retrieve()

        records = (rec for rec in self.parse(raw))
        if args.filter and args.filter != '*':
            allow = set(int(x) for x in args.filter.split(','))
            records = (rec for rec in records if rec.rtype in allow)

        output(records)



if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--debug', action='store_true')
    parser.add_argument('--host', default='http://pavlok-mvp.herokuapp.com')
    parser.add_argument('--query', default='/api/feedbacks/{fid}?access_token={token}')
    parser.add_argument('--token', default='1o2p3alkmfosdngoi23j4r2oij3komdfj9031j102j30j')
    parser.add_argument('--json', action='store_true')
    parser.add_argument('--cache', action='store_true')
    parser.add_argument('--pretty', action='store_true',
        help='output non-compact JSON with indentation etc.')
    parser.add_argument('--filter', default='*')
    parser.add_argument('--raw', action='store_true')
    parser.add_argument('fid')

    args = parser.parse_args()

    Record.debug = args.debug

    logging.basicConfig(level='DEBUG' if args.debug else 'WARN',
        format='%(asctime)s,%(msecs)03d| %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S')

    try:
        LogParser().run()

    except AppError as ex:
        print('Error: %s' % ex)
        sys.exit(1)

    except (BrokenPipeError, KeyboardInterrupt):
        pass

    except Exception as ex:
        log.exception('error: %s', ex)
        sys.exit(2)


# EOF
