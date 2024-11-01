using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;

namespace Playground {
    internal class Program {
        static Stream DecryptScsC(byte[] input) {
            MemoryStream ii = new(input);

            byte[] checksum = new byte[32];
            byte[] iv = new byte[16];

            ii.Read(checksum);
            ii.Read(iv);

            ii.Seek(4, SeekOrigin.Current); // Skip size

            using Aes aes = Aes.Create();
            aes.Key = AES_KEY;
            aes.IV = iv;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.None;
            var decryptor = aes.CreateDecryptor();
            var crypto = new CryptoStream(ii, decryptor, CryptoStreamMode.Read);
            var zlib = new ZLibStream(crypto, CompressionMode.Decompress);
            return zlib;
        }
        /// <summary>
        /// Print the first `bytes` bytes of the input stream as hex bytes. If bytes is null, the entire stream is read and printed. Every 32 bytes, a newline is printed.
        /// </summary>
        /// <param name="input"></param>
        /// <param name="bytes"></param>
        static void ReadAndPrintHexBytes(Stream input, int? bytes) {
            int n = 0;
            while (true) {
                if (n % 32 == 0) Console.WriteLine();

                int read = input.ReadByte();
                if (read == -1) break;

                Console.Write($"{read:X2} ");

                n++;
                if (bytes is not null && n >= bytes) break;
            }
        }

        public static readonly byte[] HEADER_ENCRYPTED = [0x53, 0x63, 0x73, 0x43]; // ScsC
        public static readonly byte[] HEADER_BINARY = [0x42, 0x53, 0x49, 0x49]; // BSII
        public static readonly byte[] HEADER_STRING = [0x53, 0x69, 0x69, 0x4e]; // SiiN

        public static readonly byte[] AES_KEY = [0x2a, 0x5f, 0xcb, 0x17, 0x91, 0xd2, 0x2f, 0xb6, 0x02, 0x45, 0xb3, 0xd8, 0x36, 0x9e, 0xd0, 0xb2,
                                                 0xc2, 0x73, 0x71, 0x56, 0x3f, 0xbf, 0x1f, 0x3c, 0x9e, 0xdf, 0x6b, 0x11, 0x82, 0x5a, 0x5d, 0x0a];

        static string StringifyType(int type, MemoryStream reader) {
            if(type == 0) {
                return "Invalid";
            }
            if (type == 1) {
                return "str";
            }
            if (type == 2) {
                return "str[]";
            }
            if (type == 3) {
                return "token"; // 0,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t,u,v,w,x,y,z,_
            }
            if (type == 4) {
                return "token[]";
            }
            if (type == 5) {
                return "float";
            }
            if (type == 6) {
                return "float[]";
            }
            if (type == 7) {
                return "float[2]";
            }
            if (type == 9) {
                return "float[3]";
            }
            if (type == 0xA) {
                return "float[3][]";
            }
            if (type == 0x11) {
                return "int[3]";
            }
            if (type == 0x12) {
                return "int[3][]";
            }
            if (type == 0x17) {
                return "float[4]";
            }
            if (type == 0x18) {
                return "float[4][]";
            }
            if (type == 0x19) {
                return "float[8_7]";
            }
            if (type == 0x1A) {
                return "float[8_7][]";
            }
            if (type == 0x25) {
                return "int";
            }
            if (type == 0x26) {
                return "int[]";
            }
            if (type == 0x27) {
                return "uint";
            }
            if (type == 0x28) {
                return "uint[]";
            }
            if (type == 0x2B) {
                return "short";
            }
            if (type == 0x2C) {
                return "short[]";
            }
            if (type == 0x2D) {
                return "unknown";
            }
            if (type == 0x2E) {
                return "unknown[]";
            }
            if (type == 0x2F) {
                return "uint";
            }
            if (type == 0x30) {
                return "uint[]";
            }
            if (type == 0x31) {
                return "long";
            }
            if (type == 0x32) {
                return "long[]";
            }
            if (type == 0x33) {
                return "ulong";
            }
            if (type == 0x34) {
                return "ulong[]";
            }
            if (type == 0x35) {
                return "bool";
            }
            if (type == 0x36) {
                return "bool[]";
            }
            if (type == 0x37) {
                byte[] buf = new byte[1024];
                reader.Read(buf, 0, 4);
                int itemsCount = ByteEncoder.DecodeInt32(buf);

                string s = "";

                for(int i=0; i< itemsCount; i++) {
                    reader.Read(buf, 0, 4);
                    int enumValue = ByteEncoder.DecodeInt32(buf);

                    reader.Read(buf, 0, 4);
                    int enumNameLength = ByteEncoder.DecodeInt32(buf);

                    reader.Read(buf, 0, enumNameLength);
                    string enumName = Encoding.UTF8.GetString(buf, 0, enumNameLength);

                    s += $"{enumName}={enumValue}, ";
                }

                s = s.Substring(0, s.Length - 2);

                return "enum<" + s + ">";
            }
            if (type == 0x38) {
                byte[] buf = new byte[1024];
                reader.Read(buf, 0, 4);
                int itemsCount = ByteEncoder.DecodeInt32(buf);

                string s = "";

                for (int i = 0; i < itemsCount; i++) {
                    reader.Read(buf, 0, 4);
                    int enumValue = ByteEncoder.DecodeInt32(buf);

                    reader.Read(buf, 0, 4);
                    int enumNameLength = ByteEncoder.DecodeInt32(buf);

                    reader.Read(buf, 0, enumNameLength);
                    string enumName = Encoding.UTF8.GetString(buf, 0, enumNameLength);

                    s += $"{enumName}={enumValue}, ";
                }

                s = s.Substring(0, s.Length - 2);

                return "enum<" + s + ">[]";
            }
            if (type == 0x39 || type == 0x3B) {
                return "ptr";
            }
            if (type == 0x3D) {
                return "weak_ptr";
            }
            if (type == 0x3A || type == 0x3C) {
                return "ptr[]";
            }
            if (type == 0x3E) {
                return "weak_ptr[]";
            }
            return "Unknown";
        }

        static void DumpFromHere(MemoryStream stream, string filename) {
            if (stream == null) return;
            using FileStream fs = new(filename, FileMode.Create);
            stream.CopyTo(fs);
            fs.Close();
            throw new Exception("Dumped.");
        }

        static void Main(string[] args) {
            Console.Write("File name to process: ");
            //string? fileName = Console.ReadLine();
            string fileName = "game.sii";
            if (fileName is null) return;

            byte[] data = File.ReadAllBytes(fileName);
            byte[] header = data[0..4];

            if (header.SequenceEqual(HEADER_ENCRYPTED)) {
                Console.WriteLine("Encrypted file detected. Decrypting...");

                MemoryStream ms2 = new();
                DecryptScsC(data[4..]).CopyTo(ms2);
                data = ms2.ToArray();
                header = data[0..4];
            }

            if (header.SequenceEqual(HEADER_BINARY)) {
                Console.WriteLine("Binary file detected.");
            } else if (header.SequenceEqual(HEADER_STRING)) {
                Console.WriteLine("String file detected.");
                Console.WriteLine("This code is for binary files only.");
                return;
            } else {
                Console.WriteLine("Unknown file type.");
                return;
            }

            File.WriteAllBytes("decrypted.dat", data);

            int offset = 4;
            int version = ByteEncoder.DecodeInt32(data[offset..(offset + 4)]);
            Console.WriteLine($"File Version: {version}");
            offset += 4;

            if(version != 3) {
                Console.WriteLine("Only bsii version 3 is supported.");
                return;
            }

            Console.WriteLine("Reading blocks...");
            MemoryStream ms = new(data[offset..]);    
            byte[] blockTypeBuf = new byte[4];
            byte[] buf = new byte[1024];
            Dictionary<int, string> structureNames = new();
            while (ms.Read(blockTypeBuf) == 4) {
                int blockType = ByteEncoder.DecodeInt32(blockTypeBuf);
                if(blockType == 0) { // Definition of structure, or EOF if followed by a single byte containing 0
                    byte validity = (byte)ms.ReadByte();
                    if(validity == 0) {
                        Console.WriteLine("EOF");
                        break;
                    }

                    // Read the structure
                    ms.Read(buf, 0, 4);
                    int structureId = ByteEncoder.DecodeInt32(buf);

                    ms.Read(buf, 0, 4);
                    int nameLength = ByteEncoder.DecodeInt32(buf);

                    ms.Read(buf, 0, nameLength);
                    string name = Encoding.UTF8.GetString(buf, 0, nameLength);

                    Console.WriteLine($"struct {name} {{ // ID 0x{structureId}");

                    while(true) {
                        ms.Read(buf, 0, 4);
                        int fieldTypeId = ByteEncoder.DecodeInt32(buf);
                        if (fieldTypeId == 0) break; // End of structure

                        ms.Read(buf, 0, 4);
                        int fieldNameLength = ByteEncoder.DecodeInt32(buf);

                        ms.Read(buf, 0, fieldNameLength);
                        string fieldName = Encoding.UTF8.GetString(buf, 0, fieldNameLength);
                        string stringifiedType = StringifyType(fieldTypeId, ms);

                        Console.WriteLine($"\t{stringifiedType} {fieldName}; // ID 0x{fieldTypeId:X2}");
                    }

                    Console.WriteLine("}\n");
                } else {
                    Console.WriteLine("Reached data block. Not implemented yet.");
                    break; // not implemented yet
                }
            }
        }
    }
}