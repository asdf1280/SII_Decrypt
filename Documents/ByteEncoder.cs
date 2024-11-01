using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;

namespace Playground {
    public enum ByteOrder {
        BigEndian,
        LittleEndian
    }

    public class ByteEncoder {
        public static byte[] EncodeInt16(short a, ByteOrder endian = ByteOrder.LittleEndian) {
            var buf = BitConverter.GetBytes(a);
            if(BitConverter.IsLittleEndian != (endian == ByteOrder.LittleEndian)) {
                Array.Reverse(buf);
            }
            return buf;
        }

        public static byte[] EncodeUInt16(ushort a, ByteOrder endian = ByteOrder.LittleEndian) {
            var buf = BitConverter.GetBytes(a);
            if (BitConverter.IsLittleEndian != (endian == ByteOrder.LittleEndian)) {
                Array.Reverse(buf);
            }
            return buf;
        }

        public static byte[] EncodeInt32(int a, ByteOrder endian = ByteOrder.LittleEndian) {
            var buf = BitConverter.GetBytes(a);
            if (BitConverter.IsLittleEndian != (endian == ByteOrder.LittleEndian)) {
                Array.Reverse(buf);
            }
            return buf;
        }

        public static byte[] EncodeUInt32(uint a, ByteOrder endian = ByteOrder.LittleEndian) {
            var buf = BitConverter.GetBytes(a);
            if (BitConverter.IsLittleEndian != (endian == ByteOrder.LittleEndian)) {
                Array.Reverse(buf);
            }
            return buf;
        }

        public static byte[] EncodeInt64(long a, ByteOrder endian = ByteOrder.LittleEndian) {
            var buf = BitConverter.GetBytes(a);
            if (BitConverter.IsLittleEndian != (endian == ByteOrder.LittleEndian)) {
                Array.Reverse(buf);
            }
            return buf;
        }

        public static byte[] EncodeUInt64(ulong a, ByteOrder endian = ByteOrder.LittleEndian) {
            var buf = BitConverter.GetBytes(a);
            if (BitConverter.IsLittleEndian != (endian == ByteOrder.LittleEndian)) {
                Array.Reverse(buf);
            }
            return buf;
        }

        public static byte[] EncodeInt128(Int128 a, ByteOrder endian = ByteOrder.LittleEndian) {
            var buf = new byte[16];
            for (int i = 0; i < 16; i++) {
                buf[i] = (byte)(a & 0xFF);
                a >>= 8;
            }
            if(endian == ByteOrder.LittleEndian) {
                Array.Reverse(buf);
            }
            return buf;
        }

        public static byte[] EncodeUInt128(UInt128 a, ByteOrder endian = ByteOrder.LittleEndian) {
            var buf = new byte[16];
            for (int i = 0; i < 16; i++) {
                buf[i] = (byte)(a & 0xFF);
                a >>= 8;
            }
            if (endian == ByteOrder.LittleEndian) {
                Array.Reverse(buf);
            }
            return buf;
        }

        public static short DecodeInt16(byte[] buf, ByteOrder endian = ByteOrder.LittleEndian) {
            if(BitConverter.IsLittleEndian != (endian == ByteOrder.LittleEndian)) {
                buf = buf.Reverse().ToArray();
            }
            return BitConverter.ToInt16(buf);
        }

        public static ushort DecodeUInt16(byte[] buf, ByteOrder endian = ByteOrder.LittleEndian) {
            if (BitConverter.IsLittleEndian != (endian == ByteOrder.LittleEndian)) {
                buf = buf.Reverse().ToArray();
            }
            return BitConverter.ToUInt16(buf);
        }

        public static int DecodeInt32(byte[] buf, ByteOrder endian = ByteOrder.LittleEndian) {
            if (BitConverter.IsLittleEndian != (endian == ByteOrder.LittleEndian)) {
                buf = buf.Reverse().ToArray();
            }
            return BitConverter.ToInt32(buf);
        }

        public static uint DecodeUInt32(byte[] buf, ByteOrder endian = ByteOrder.LittleEndian) {
            if (BitConverter.IsLittleEndian != (endian == ByteOrder.LittleEndian)) {
                buf = buf.Reverse().ToArray();
            }
            return BitConverter.ToUInt32(buf);
        }

        public static long DecodeInt64(byte[] buf, ByteOrder endian = ByteOrder.LittleEndian) {
            if (BitConverter.IsLittleEndian != (endian == ByteOrder.LittleEndian)) {
                buf = buf.Reverse().ToArray();
            }
            return BitConverter.ToInt64(buf);
        }

        public static ulong DecodeUInt64(byte[] buf, ByteOrder endian = ByteOrder.LittleEndian) {
            if (BitConverter.IsLittleEndian != (endian == ByteOrder.LittleEndian)) {
                buf = buf.Reverse().ToArray();
            }
            return BitConverter.ToUInt64(buf);
        }

        public static Int128 DecodeInt128(byte[] buf, ByteOrder endian = ByteOrder.LittleEndian) {
            if (buf.Length != 16) {
                throw new ArgumentException("buf must be 16 bytes long");
            }
            if (BitConverter.IsLittleEndian != (endian == ByteOrder.LittleEndian)) {
                buf = buf.Reverse().ToArray();
            }
            UInt128 result = 0;
            for (int i = 15; i >= 0; i--) {
                result <<= 8;
                result |= buf[i];
            }
            return (Int128)result;
        }

        public static UInt128 DecodeUInt128(byte[] buf, ByteOrder endian = ByteOrder.LittleEndian) {
            if (buf.Length != 16) {
                throw new ArgumentException("buf must be 16 bytes long");
            }
            if (BitConverter.IsLittleEndian != (endian == ByteOrder.LittleEndian)) {
                buf = buf.Reverse().ToArray();
            }
            UInt128 result = 0;
            for (int i = 15; i >= 0; i--) {
                result <<= 8;
                result |= buf[i];
            }
            return result;
        }
    }
}