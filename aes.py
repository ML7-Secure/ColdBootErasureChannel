import itertools
import operator
import functools
import random
import base64

# The MIT License (MIT)
#
# Copyright (c) 2014 Richard Moore
# Modified (2020) by Charles Bouillaguet 

#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

# This is a pure-Python implementation of the AES algorithm and AES common
# modes of operation.

# See: https://en.wikipedia.org/wiki/Advanced_Encryption_Standard

# Round constant words
RCON = [ 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]

# S-box and Inverse S-box (S is for Substitution)
S = [ 0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 ]
# = [   00,   01, ...                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         ,   ff ]
# Transformations for encryption == ShiftRows
T = [
    [ 0xc66363a5, 0xf87c7c84, 0xee777799, 0xf67b7b8d, 0xfff2f20d, 0xd66b6bbd, 0xde6f6fb1, 0x91c5c554, 0x60303050, 0x02010103, 0xce6767a9, 0x562b2b7d, 0xe7fefe19, 0xb5d7d762, 0x4dababe6, 0xec76769a, 0x8fcaca45, 0x1f82829d, 0x89c9c940, 0xfa7d7d87, 0xeffafa15, 0xb25959eb, 0x8e4747c9, 0xfbf0f00b, 0x41adadec, 0xb3d4d467, 0x5fa2a2fd, 0x45afafea, 0x239c9cbf, 0x53a4a4f7, 0xe4727296, 0x9bc0c05b, 0x75b7b7c2, 0xe1fdfd1c, 0x3d9393ae, 0x4c26266a, 0x6c36365a, 0x7e3f3f41, 0xf5f7f702, 0x83cccc4f, 0x6834345c, 0x51a5a5f4, 0xd1e5e534, 0xf9f1f108, 0xe2717193, 0xabd8d873, 0x62313153, 0x2a15153f, 0x0804040c, 0x95c7c752, 0x46232365, 0x9dc3c35e, 0x30181828, 0x379696a1, 0x0a05050f, 0x2f9a9ab5, 0x0e070709, 0x24121236, 0x1b80809b, 0xdfe2e23d, 0xcdebeb26, 0x4e272769, 0x7fb2b2cd, 0xea75759f, 0x1209091b, 0x1d83839e, 0x582c2c74, 0x341a1a2e, 0x361b1b2d, 0xdc6e6eb2, 0xb45a5aee, 0x5ba0a0fb, 0xa45252f6, 0x763b3b4d, 0xb7d6d661, 0x7db3b3ce, 0x5229297b, 0xdde3e33e, 0x5e2f2f71, 0x13848497, 0xa65353f5, 0xb9d1d168, 0x00000000, 0xc1eded2c, 0x40202060, 0xe3fcfc1f, 0x79b1b1c8, 0xb65b5bed, 0xd46a6abe, 0x8dcbcb46, 0x67bebed9, 0x7239394b, 0x944a4ade, 0x984c4cd4, 0xb05858e8, 0x85cfcf4a, 0xbbd0d06b, 0xc5efef2a, 0x4faaaae5, 0xedfbfb16, 0x864343c5, 0x9a4d4dd7, 0x66333355, 0x11858594, 0x8a4545cf, 0xe9f9f910, 0x04020206, 0xfe7f7f81, 0xa05050f0, 0x783c3c44, 0x259f9fba, 0x4ba8a8e3, 0xa25151f3, 0x5da3a3fe, 0x804040c0, 0x058f8f8a, 0x3f9292ad, 0x219d9dbc, 0x70383848, 0xf1f5f504, 0x63bcbcdf, 0x77b6b6c1, 0xafdada75, 0x42212163, 0x20101030, 0xe5ffff1a, 0xfdf3f30e, 0xbfd2d26d, 0x81cdcd4c, 0x180c0c14, 0x26131335, 0xc3ecec2f, 0xbe5f5fe1, 0x359797a2, 0x884444cc, 0x2e171739, 0x93c4c457, 0x55a7a7f2, 0xfc7e7e82, 0x7a3d3d47, 0xc86464ac, 0xba5d5de7, 0x3219192b, 0xe6737395, 0xc06060a0, 0x19818198, 0x9e4f4fd1, 0xa3dcdc7f, 0x44222266, 0x542a2a7e, 0x3b9090ab, 0x0b888883, 0x8c4646ca, 0xc7eeee29, 0x6bb8b8d3, 0x2814143c, 0xa7dede79, 0xbc5e5ee2, 0x160b0b1d, 0xaddbdb76, 0xdbe0e03b, 0x64323256, 0x743a3a4e, 0x140a0a1e, 0x924949db, 0x0c06060a, 0x4824246c, 0xb85c5ce4, 0x9fc2c25d, 0xbdd3d36e, 0x43acacef, 0xc46262a6, 0x399191a8, 0x319595a4, 0xd3e4e437, 0xf279798b, 0xd5e7e732, 0x8bc8c843, 0x6e373759, 0xda6d6db7, 0x018d8d8c, 0xb1d5d564, 0x9c4e4ed2, 0x49a9a9e0, 0xd86c6cb4, 0xac5656fa, 0xf3f4f407, 0xcfeaea25, 0xca6565af, 0xf47a7a8e, 0x47aeaee9, 0x10080818, 0x6fbabad5, 0xf0787888, 0x4a25256f, 0x5c2e2e72, 0x381c1c24, 0x57a6a6f1, 0x73b4b4c7, 0x97c6c651, 0xcbe8e823, 0xa1dddd7c, 0xe874749c, 0x3e1f1f21, 0x964b4bdd, 0x61bdbddc, 0x0d8b8b86, 0x0f8a8a85, 0xe0707090, 0x7c3e3e42, 0x71b5b5c4, 0xcc6666aa, 0x904848d8, 0x06030305, 0xf7f6f601, 0x1c0e0e12, 0xc26161a3, 0x6a35355f, 0xae5757f9, 0x69b9b9d0, 0x17868691, 0x99c1c158, 0x3a1d1d27, 0x279e9eb9, 0xd9e1e138, 0xebf8f813, 0x2b9898b3, 0x22111133, 0xd26969bb, 0xa9d9d970, 0x078e8e89, 0x339494a7, 0x2d9b9bb6, 0x3c1e1e22, 0x15878792, 0xc9e9e920, 0x87cece49, 0xaa5555ff, 0x50282878, 0xa5dfdf7a, 0x038c8c8f, 0x59a1a1f8, 0x09898980, 0x1a0d0d17, 0x65bfbfda, 0xd7e6e631, 0x844242c6, 0xd06868b8, 0x824141c3, 0x299999b0, 0x5a2d2d77, 0x1e0f0f11, 0x7bb0b0cb, 0xa85454fc, 0x6dbbbbd6, 0x2c16163a ],
    [ 0xa5c66363, 0x84f87c7c, 0x99ee7777, 0x8df67b7b, 0x0dfff2f2, 0xbdd66b6b, 0xb1de6f6f, 0x5491c5c5, 0x50603030, 0x03020101, 0xa9ce6767, 0x7d562b2b, 0x19e7fefe, 0x62b5d7d7, 0xe64dabab, 0x9aec7676, 0x458fcaca, 0x9d1f8282, 0x4089c9c9, 0x87fa7d7d, 0x15effafa, 0xebb25959, 0xc98e4747, 0x0bfbf0f0, 0xec41adad, 0x67b3d4d4, 0xfd5fa2a2, 0xea45afaf, 0xbf239c9c, 0xf753a4a4, 0x96e47272, 0x5b9bc0c0, 0xc275b7b7, 0x1ce1fdfd, 0xae3d9393, 0x6a4c2626, 0x5a6c3636, 0x417e3f3f, 0x02f5f7f7, 0x4f83cccc, 0x5c683434, 0xf451a5a5, 0x34d1e5e5, 0x08f9f1f1, 0x93e27171, 0x73abd8d8, 0x53623131, 0x3f2a1515, 0x0c080404, 0x5295c7c7, 0x65462323, 0x5e9dc3c3, 0x28301818, 0xa1379696, 0x0f0a0505, 0xb52f9a9a, 0x090e0707, 0x36241212, 0x9b1b8080, 0x3ddfe2e2, 0x26cdebeb, 0x694e2727, 0xcd7fb2b2, 0x9fea7575, 0x1b120909, 0x9e1d8383, 0x74582c2c, 0x2e341a1a, 0x2d361b1b, 0xb2dc6e6e, 0xeeb45a5a, 0xfb5ba0a0, 0xf6a45252, 0x4d763b3b, 0x61b7d6d6, 0xce7db3b3, 0x7b522929, 0x3edde3e3, 0x715e2f2f, 0x97138484, 0xf5a65353, 0x68b9d1d1, 0x00000000, 0x2cc1eded, 0x60402020, 0x1fe3fcfc, 0xc879b1b1, 0xedb65b5b, 0xbed46a6a, 0x468dcbcb, 0xd967bebe, 0x4b723939, 0xde944a4a, 0xd4984c4c, 0xe8b05858, 0x4a85cfcf, 0x6bbbd0d0, 0x2ac5efef, 0xe54faaaa, 0x16edfbfb, 0xc5864343, 0xd79a4d4d, 0x55663333, 0x94118585, 0xcf8a4545, 0x10e9f9f9, 0x06040202, 0x81fe7f7f, 0xf0a05050, 0x44783c3c, 0xba259f9f, 0xe34ba8a8, 0xf3a25151, 0xfe5da3a3, 0xc0804040, 0x8a058f8f, 0xad3f9292, 0xbc219d9d, 0x48703838, 0x04f1f5f5, 0xdf63bcbc, 0xc177b6b6, 0x75afdada, 0x63422121, 0x30201010, 0x1ae5ffff, 0x0efdf3f3, 0x6dbfd2d2, 0x4c81cdcd, 0x14180c0c, 0x35261313, 0x2fc3ecec, 0xe1be5f5f, 0xa2359797, 0xcc884444, 0x392e1717, 0x5793c4c4, 0xf255a7a7, 0x82fc7e7e, 0x477a3d3d, 0xacc86464, 0xe7ba5d5d, 0x2b321919, 0x95e67373, 0xa0c06060, 0x98198181, 0xd19e4f4f, 0x7fa3dcdc, 0x66442222, 0x7e542a2a, 0xab3b9090, 0x830b8888, 0xca8c4646, 0x29c7eeee, 0xd36bb8b8, 0x3c281414, 0x79a7dede, 0xe2bc5e5e, 0x1d160b0b, 0x76addbdb, 0x3bdbe0e0, 0x56643232, 0x4e743a3a, 0x1e140a0a, 0xdb924949, 0x0a0c0606, 0x6c482424, 0xe4b85c5c, 0x5d9fc2c2, 0x6ebdd3d3, 0xef43acac, 0xa6c46262, 0xa8399191, 0xa4319595, 0x37d3e4e4, 0x8bf27979, 0x32d5e7e7, 0x438bc8c8, 0x596e3737, 0xb7da6d6d, 0x8c018d8d, 0x64b1d5d5, 0xd29c4e4e, 0xe049a9a9, 0xb4d86c6c, 0xfaac5656, 0x07f3f4f4, 0x25cfeaea, 0xafca6565, 0x8ef47a7a, 0xe947aeae, 0x18100808, 0xd56fbaba, 0x88f07878, 0x6f4a2525, 0x725c2e2e, 0x24381c1c, 0xf157a6a6, 0xc773b4b4, 0x5197c6c6, 0x23cbe8e8, 0x7ca1dddd, 0x9ce87474, 0x213e1f1f, 0xdd964b4b, 0xdc61bdbd, 0x860d8b8b, 0x850f8a8a, 0x90e07070, 0x427c3e3e, 0xc471b5b5, 0xaacc6666, 0xd8904848, 0x05060303, 0x01f7f6f6, 0x121c0e0e, 0xa3c26161, 0x5f6a3535, 0xf9ae5757, 0xd069b9b9, 0x91178686, 0x5899c1c1, 0x273a1d1d, 0xb9279e9e, 0x38d9e1e1, 0x13ebf8f8, 0xb32b9898, 0x33221111, 0xbbd26969, 0x70a9d9d9, 0x89078e8e, 0xa7339494, 0xb62d9b9b, 0x223c1e1e, 0x92158787, 0x20c9e9e9, 0x4987cece, 0xffaa5555, 0x78502828, 0x7aa5dfdf, 0x8f038c8c, 0xf859a1a1, 0x80098989, 0x171a0d0d, 0xda65bfbf, 0x31d7e6e6, 0xc6844242, 0xb8d06868, 0xc3824141, 0xb0299999, 0x775a2d2d, 0x111e0f0f, 0xcb7bb0b0, 0xfca85454, 0xd66dbbbb, 0x3a2c1616 ],
    [ 0x63a5c663, 0x7c84f87c, 0x7799ee77, 0x7b8df67b, 0xf20dfff2, 0x6bbdd66b, 0x6fb1de6f, 0xc55491c5, 0x30506030, 0x01030201, 0x67a9ce67, 0x2b7d562b, 0xfe19e7fe, 0xd762b5d7, 0xabe64dab, 0x769aec76, 0xca458fca, 0x829d1f82, 0xc94089c9, 0x7d87fa7d, 0xfa15effa, 0x59ebb259, 0x47c98e47, 0xf00bfbf0, 0xadec41ad, 0xd467b3d4, 0xa2fd5fa2, 0xafea45af, 0x9cbf239c, 0xa4f753a4, 0x7296e472, 0xc05b9bc0, 0xb7c275b7, 0xfd1ce1fd, 0x93ae3d93, 0x266a4c26, 0x365a6c36, 0x3f417e3f, 0xf702f5f7, 0xcc4f83cc, 0x345c6834, 0xa5f451a5, 0xe534d1e5, 0xf108f9f1, 0x7193e271, 0xd873abd8, 0x31536231, 0x153f2a15, 0x040c0804, 0xc75295c7, 0x23654623, 0xc35e9dc3, 0x18283018, 0x96a13796, 0x050f0a05, 0x9ab52f9a, 0x07090e07, 0x12362412, 0x809b1b80, 0xe23ddfe2, 0xeb26cdeb, 0x27694e27, 0xb2cd7fb2, 0x759fea75, 0x091b1209, 0x839e1d83, 0x2c74582c, 0x1a2e341a, 0x1b2d361b, 0x6eb2dc6e, 0x5aeeb45a, 0xa0fb5ba0, 0x52f6a452, 0x3b4d763b, 0xd661b7d6, 0xb3ce7db3, 0x297b5229, 0xe33edde3, 0x2f715e2f, 0x84971384, 0x53f5a653, 0xd168b9d1, 0x00000000, 0xed2cc1ed, 0x20604020, 0xfc1fe3fc, 0xb1c879b1, 0x5bedb65b, 0x6abed46a, 0xcb468dcb, 0xbed967be, 0x394b7239, 0x4ade944a, 0x4cd4984c, 0x58e8b058, 0xcf4a85cf, 0xd06bbbd0, 0xef2ac5ef, 0xaae54faa, 0xfb16edfb, 0x43c58643, 0x4dd79a4d, 0x33556633, 0x85941185, 0x45cf8a45, 0xf910e9f9, 0x02060402, 0x7f81fe7f, 0x50f0a050, 0x3c44783c, 0x9fba259f, 0xa8e34ba8, 0x51f3a251, 0xa3fe5da3, 0x40c08040, 0x8f8a058f, 0x92ad3f92, 0x9dbc219d, 0x38487038, 0xf504f1f5, 0xbcdf63bc, 0xb6c177b6, 0xda75afda, 0x21634221, 0x10302010, 0xff1ae5ff, 0xf30efdf3, 0xd26dbfd2, 0xcd4c81cd, 0x0c14180c, 0x13352613, 0xec2fc3ec, 0x5fe1be5f, 0x97a23597, 0x44cc8844, 0x17392e17, 0xc45793c4, 0xa7f255a7, 0x7e82fc7e, 0x3d477a3d, 0x64acc864, 0x5de7ba5d, 0x192b3219, 0x7395e673, 0x60a0c060, 0x81981981, 0x4fd19e4f, 0xdc7fa3dc, 0x22664422, 0x2a7e542a, 0x90ab3b90, 0x88830b88, 0x46ca8c46, 0xee29c7ee, 0xb8d36bb8, 0x143c2814, 0xde79a7de, 0x5ee2bc5e, 0x0b1d160b, 0xdb76addb, 0xe03bdbe0, 0x32566432, 0x3a4e743a, 0x0a1e140a, 0x49db9249, 0x060a0c06, 0x246c4824, 0x5ce4b85c, 0xc25d9fc2, 0xd36ebdd3, 0xacef43ac, 0x62a6c462, 0x91a83991, 0x95a43195, 0xe437d3e4, 0x798bf279, 0xe732d5e7, 0xc8438bc8, 0x37596e37, 0x6db7da6d, 0x8d8c018d, 0xd564b1d5, 0x4ed29c4e, 0xa9e049a9, 0x6cb4d86c, 0x56faac56, 0xf407f3f4, 0xea25cfea, 0x65afca65, 0x7a8ef47a, 0xaee947ae, 0x08181008, 0xbad56fba, 0x7888f078, 0x256f4a25, 0x2e725c2e, 0x1c24381c, 0xa6f157a6, 0xb4c773b4, 0xc65197c6, 0xe823cbe8, 0xdd7ca1dd, 0x749ce874, 0x1f213e1f, 0x4bdd964b, 0xbddc61bd, 0x8b860d8b, 0x8a850f8a, 0x7090e070, 0x3e427c3e, 0xb5c471b5, 0x66aacc66, 0x48d89048, 0x03050603, 0xf601f7f6, 0x0e121c0e, 0x61a3c261, 0x355f6a35, 0x57f9ae57, 0xb9d069b9, 0x86911786, 0xc15899c1, 0x1d273a1d, 0x9eb9279e, 0xe138d9e1, 0xf813ebf8, 0x98b32b98, 0x11332211, 0x69bbd269, 0xd970a9d9, 0x8e89078e, 0x94a73394, 0x9bb62d9b, 0x1e223c1e, 0x87921587, 0xe920c9e9, 0xce4987ce, 0x55ffaa55, 0x28785028, 0xdf7aa5df, 0x8c8f038c, 0xa1f859a1, 0x89800989, 0x0d171a0d, 0xbfda65bf, 0xe631d7e6, 0x42c68442, 0x68b8d068, 0x41c38241, 0x99b02999, 0x2d775a2d, 0x0f111e0f, 0xb0cb7bb0, 0x54fca854, 0xbbd66dbb, 0x163a2c16 ],
    [ 0x6363a5c6, 0x7c7c84f8, 0x777799ee, 0x7b7b8df6, 0xf2f20dff, 0x6b6bbdd6, 0x6f6fb1de, 0xc5c55491, 0x30305060, 0x01010302, 0x6767a9ce, 0x2b2b7d56, 0xfefe19e7, 0xd7d762b5, 0xababe64d, 0x76769aec, 0xcaca458f, 0x82829d1f, 0xc9c94089, 0x7d7d87fa, 0xfafa15ef, 0x5959ebb2, 0x4747c98e, 0xf0f00bfb, 0xadadec41, 0xd4d467b3, 0xa2a2fd5f, 0xafafea45, 0x9c9cbf23, 0xa4a4f753, 0x727296e4, 0xc0c05b9b, 0xb7b7c275, 0xfdfd1ce1, 0x9393ae3d, 0x26266a4c, 0x36365a6c, 0x3f3f417e, 0xf7f702f5, 0xcccc4f83, 0x34345c68, 0xa5a5f451, 0xe5e534d1, 0xf1f108f9, 0x717193e2, 0xd8d873ab, 0x31315362, 0x15153f2a, 0x04040c08, 0xc7c75295, 0x23236546, 0xc3c35e9d, 0x18182830, 0x9696a137, 0x05050f0a, 0x9a9ab52f, 0x0707090e, 0x12123624, 0x80809b1b, 0xe2e23ddf, 0xebeb26cd, 0x2727694e, 0xb2b2cd7f, 0x75759fea, 0x09091b12, 0x83839e1d, 0x2c2c7458, 0x1a1a2e34, 0x1b1b2d36, 0x6e6eb2dc, 0x5a5aeeb4, 0xa0a0fb5b, 0x5252f6a4, 0x3b3b4d76, 0xd6d661b7, 0xb3b3ce7d, 0x29297b52, 0xe3e33edd, 0x2f2f715e, 0x84849713, 0x5353f5a6, 0xd1d168b9, 0x00000000, 0xeded2cc1, 0x20206040, 0xfcfc1fe3, 0xb1b1c879, 0x5b5bedb6, 0x6a6abed4, 0xcbcb468d, 0xbebed967, 0x39394b72, 0x4a4ade94, 0x4c4cd498, 0x5858e8b0, 0xcfcf4a85, 0xd0d06bbb, 0xefef2ac5, 0xaaaae54f, 0xfbfb16ed, 0x4343c586, 0x4d4dd79a, 0x33335566, 0x85859411, 0x4545cf8a, 0xf9f910e9, 0x02020604, 0x7f7f81fe, 0x5050f0a0, 0x3c3c4478, 0x9f9fba25, 0xa8a8e34b, 0x5151f3a2, 0xa3a3fe5d, 0x4040c080, 0x8f8f8a05, 0x9292ad3f, 0x9d9dbc21, 0x38384870, 0xf5f504f1, 0xbcbcdf63, 0xb6b6c177, 0xdada75af, 0x21216342, 0x10103020, 0xffff1ae5, 0xf3f30efd, 0xd2d26dbf, 0xcdcd4c81, 0x0c0c1418, 0x13133526, 0xecec2fc3, 0x5f5fe1be, 0x9797a235, 0x4444cc88, 0x1717392e, 0xc4c45793, 0xa7a7f255, 0x7e7e82fc, 0x3d3d477a, 0x6464acc8, 0x5d5de7ba, 0x19192b32, 0x737395e6, 0x6060a0c0, 0x81819819, 0x4f4fd19e, 0xdcdc7fa3, 0x22226644, 0x2a2a7e54, 0x9090ab3b, 0x8888830b, 0x4646ca8c, 0xeeee29c7, 0xb8b8d36b, 0x14143c28, 0xdede79a7, 0x5e5ee2bc, 0x0b0b1d16, 0xdbdb76ad, 0xe0e03bdb, 0x32325664, 0x3a3a4e74, 0x0a0a1e14, 0x4949db92, 0x06060a0c, 0x24246c48, 0x5c5ce4b8, 0xc2c25d9f, 0xd3d36ebd, 0xacacef43, 0x6262a6c4, 0x9191a839, 0x9595a431, 0xe4e437d3, 0x79798bf2, 0xe7e732d5, 0xc8c8438b, 0x3737596e, 0x6d6db7da, 0x8d8d8c01, 0xd5d564b1, 0x4e4ed29c, 0xa9a9e049, 0x6c6cb4d8, 0x5656faac, 0xf4f407f3, 0xeaea25cf, 0x6565afca, 0x7a7a8ef4, 0xaeaee947, 0x08081810, 0xbabad56f, 0x787888f0, 0x25256f4a, 0x2e2e725c, 0x1c1c2438, 0xa6a6f157, 0xb4b4c773, 0xc6c65197, 0xe8e823cb, 0xdddd7ca1, 0x74749ce8, 0x1f1f213e, 0x4b4bdd96, 0xbdbddc61, 0x8b8b860d, 0x8a8a850f, 0x707090e0, 0x3e3e427c, 0xb5b5c471, 0x6666aacc, 0x4848d890, 0x03030506, 0xf6f601f7, 0x0e0e121c, 0x6161a3c2, 0x35355f6a, 0x5757f9ae, 0xb9b9d069, 0x86869117, 0xc1c15899, 0x1d1d273a, 0x9e9eb927, 0xe1e138d9, 0xf8f813eb, 0x9898b32b, 0x11113322, 0x6969bbd2, 0xd9d970a9, 0x8e8e8907, 0x9494a733, 0x9b9bb62d, 0x1e1e223c, 0x87879215, 0xe9e920c9, 0xcece4987, 0x5555ffaa, 0x28287850, 0xdfdf7aa5, 0x8c8c8f03, 0xa1a1f859, 0x89898009, 0x0d0d171a, 0xbfbfda65, 0xe6e631d7, 0x4242c684, 0x6868b8d0, 0x4141c382, 0x9999b029, 0x2d2d775a, 0x0f0f111e, 0xb0b0cb7b, 0x5454fca8, 0xbbbbd66d, 0x16163a2c ],
]

# convert ints to bytes
for i in range(4):
    for j in range(256):
        T[i][j] = T[i][j].to_bytes(4, byteorder='big')


def XOR(*seqs):
    """
    XOR toghether an arbitrary number of bytes()
    """
    return bytearray([functools.reduce(operator.xor, t, 0) for t in zip(*seqs)])


def subs(S, t):
    """
    returns S[t[0]], S[t[1]], ...
    """
    return bytearray(S[x] for x in t)


class AES:
    '''
    Encapsulates the AES-128 block cipher.
    Cf http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf
    

    >>> import base64
    >>> key = bytes.fromhex("00000000000000000000000000000000")
    >>> a = AES(key)
    >>> plaintext = bytes.fromhex("80000000000000000000000000000000")
    >>> ciphertext = bytes.fromhex("3ad78e726c1ec02b7ebfe92b23d9ec34")
    >>> assert a.encrypt(plaintext) == ciphertext
    '''

    # expanded keys --- subkeys[i][j] is the j-th column of the i-th subkey
    subkeys = None
  

    def __init__(self, key):
        if len(key) != 16:
            raise ValueError('Invalid key size')

        # Convert the key into four 32-bit words == 4 byte word
        tk = [key[i:i + 4] for i in range(0, 16, 4)]
        # key[i:i + 4] : slice == from i to i+4 (i+4 excluded)

        # Copy values into round key arrays
        self.subkeys = []
        self.subkeys.append([tk[i] for i in range(4)])

        # Key expansion (fips-197 section 5.2)
        for r in range(10):
            tt = tk[3]
            core = subs(S, [tt[1], tt[2], tt[3], tt[0]])

            core[0] ^= RCON[r]

            tk[0] = XOR(tk[0], core)
            tk[1] = XOR(tk[1], tk[0])
            tk[2] = XOR(tk[2], tk[1])
            tk[3] = XOR(tk[3], tk[2])

            self.subkeys.append([x for x in tk])

    
    def encrypt(self, plaintext):   
        ''' 
        Encrypt a block of plain text using the AES-128 block cipher.    
        '''
        if len(plaintext) != 16:
            raise ValueError('wrong block length')

        # XOR first subkey
        state = [XOR(plaintext[4*i:4*i + 4], self.subkeys[0][i]) for i in range(4)]
        
        # Apply round transforms
        for r in range(1, 10):
            # process each column (SB + SR + MC)
            intermediate = []
            for i in range(4):
                intermediate.append(XOR(*[T[j][state[(i + j) % 4][j]] for j in range(4)]))
            state = [XOR(intermediate[i], self.subkeys[r][i]) for i in range(4)]

        # The last round is special (no MixColumn)
        output = bytearray()
        # process each column
        for i in range(4): 
            shifted = bytes(state[(i + j) % 4][j] for j in range(4))
            foo = XOR(subs(S, shifted), self.subkeys[10][i])
            output.extend(foo)

        return output


def AES_CTR(K, IV):
    i = int.from_bytes(IV, 'big')
    block_cipher = AES(K)
    while True:
        block_in = i.to_bytes(16, 'big')
        block_out = block_cipher.encrypt(block_in)
        for x in block_out:
            yield x
        i += 1


def test_vectors():
        key = base64.b16decode("00000000000000000000000000000000")
        a = AES(key)
        print(a.subkeys)
        
        plaintext = [
            '80000000000000000000000000000000',     
            'c0000000000000000000000000000000',     
            'e0000000000000000000000000000000',     
            'f0000000000000000000000000000000',     
            'f8000000000000000000000000000000',     
            'fc000000000000000000000000000000',     
            'fe000000000000000000000000000000',     
            'ff000000000000000000000000000000',     
            'ff800000000000000000000000000000',     
            'ffc00000000000000000000000000000',     
            'ffe00000000000000000000000000000',     
            'fff00000000000000000000000000000',     
            'fff80000000000000000000000000000',     
            'fffc0000000000000000000000000000',     
            'fffe0000000000000000000000000000',     
            'ffff0000000000000000000000000000',     
            'ffff8000000000000000000000000000',     
            'ffffc000000000000000000000000000',     
            'ffffe000000000000000000000000000',     
            'fffff000000000000000000000000000',     
            'fffff800000000000000000000000000',     
            'fffffc00000000000000000000000000',     
            'fffffe00000000000000000000000000',     
            'ffffff00000000000000000000000000',     
            'ffffff80000000000000000000000000',     
            'ffffffc0000000000000000000000000',     
            'ffffffe0000000000000000000000000',     
            'fffffff0000000000000000000000000',     
            'fffffff8000000000000000000000000',     
            'fffffffc000000000000000000000000',     
            'fffffffe000000000000000000000000',     
            'ffffffff000000000000000000000000',     
            'ffffffff800000000000000000000000',     
            'ffffffffc00000000000000000000000',     
            'ffffffffe00000000000000000000000',     
            'fffffffff00000000000000000000000',     
            'fffffffff80000000000000000000000',     
            'fffffffffc0000000000000000000000',     
            'fffffffffe0000000000000000000000',     
            'ffffffffff0000000000000000000000',     
            'ffffffffff8000000000000000000000',     
            'ffffffffffc000000000000000000000',     
            'ffffffffffe000000000000000000000',     
            'fffffffffff000000000000000000000',     
            'fffffffffff800000000000000000000',     
            'fffffffffffc00000000000000000000',     
            'fffffffffffe00000000000000000000',     
            'ffffffffffff00000000000000000000',     
            'ffffffffffff80000000000000000000',     
            'ffffffffffffc0000000000000000000',     
            'ffffffffffffe0000000000000000000',     
            'fffffffffffff0000000000000000000',     
            'fffffffffffff8000000000000000000',     
            'fffffffffffffc000000000000000000',     
            'fffffffffffffe000000000000000000',     
            'ffffffffffffff000000000000000000',     
            'ffffffffffffff800000000000000000',     
            'ffffffffffffffc00000000000000000',     
            'ffffffffffffffe00000000000000000',     
            'fffffffffffffff00000000000000000',     
            'fffffffffffffff80000000000000000',     
            'fffffffffffffffc0000000000000000',     
            'fffffffffffffffe0000000000000000',     
            'ffffffffffffffff0000000000000000',     
            'ffffffffffffffff8000000000000000',     
            'ffffffffffffffffc000000000000000',     
            'ffffffffffffffffe000000000000000',     
            'fffffffffffffffff000000000000000',     
            'fffffffffffffffff800000000000000',     
            'fffffffffffffffffc00000000000000',     
            'fffffffffffffffffe00000000000000',     
            'ffffffffffffffffff00000000000000',     
            'ffffffffffffffffff80000000000000',     
            'ffffffffffffffffffc0000000000000',     
            'ffffffffffffffffffe0000000000000',     
            'fffffffffffffffffff0000000000000',     
            'fffffffffffffffffff8000000000000',     
            'fffffffffffffffffffc000000000000',     
            'fffffffffffffffffffe000000000000', 
            'ffffffffffffffffffff000000000000', 
            'ffffffffffffffffffff800000000000', 
            'ffffffffffffffffffffc00000000000', 
            'ffffffffffffffffffffe00000000000', 
            'fffffffffffffffffffff00000000000', 
            'fffffffffffffffffffff80000000000', 
            'fffffffffffffffffffffc0000000000', 
            'fffffffffffffffffffffe0000000000', 
            'ffffffffffffffffffffff0000000000', 
            'ffffffffffffffffffffff8000000000', 
            'ffffffffffffffffffffffc000000000', 
            'ffffffffffffffffffffffe000000000', 
            'fffffffffffffffffffffff000000000', 
            'fffffffffffffffffffffff800000000', 
            'fffffffffffffffffffffffc00000000', 
            'fffffffffffffffffffffffe00000000', 
            'ffffffffffffffffffffffff00000000', 
            'ffffffffffffffffffffffff80000000', 
            'ffffffffffffffffffffffffc0000000', 
            'ffffffffffffffffffffffffe0000000', 
            'fffffffffffffffffffffffff0000000', 
            'fffffffffffffffffffffffff8000000', 
            'fffffffffffffffffffffffffc000000', 
            'fffffffffffffffffffffffffe000000', 
            'ffffffffffffffffffffffffff000000', 
            'ffffffffffffffffffffffffff800000', 
            'ffffffffffffffffffffffffffc00000', 
            'ffffffffffffffffffffffffffe00000', 
            'fffffffffffffffffffffffffff00000', 
            'fffffffffffffffffffffffffff80000', 
            'fffffffffffffffffffffffffffc0000', 
            'fffffffffffffffffffffffffffe0000', 
            'ffffffffffffffffffffffffffff0000', 
            'ffffffffffffffffffffffffffff8000', 
            'ffffffffffffffffffffffffffffc000', 
            'ffffffffffffffffffffffffffffe000', 
            'fffffffffffffffffffffffffffff000', 
            'fffffffffffffffffffffffffffff800', 
            'fffffffffffffffffffffffffffffc00', 
            'fffffffffffffffffffffffffffffe00', 
            'ffffffffffffffffffffffffffffff00', 
            'ffffffffffffffffffffffffffffff80', 
            'ffffffffffffffffffffffffffffffc0', 
            'ffffffffffffffffffffffffffffffe0', 
            'fffffffffffffffffffffffffffffff0', 
            'fffffffffffffffffffffffffffffff8', 
            'fffffffffffffffffffffffffffffffc', 
            'fffffffffffffffffffffffffffffffe', 
            'ffffffffffffffffffffffffffffffff', 
        ]
        ciphertext = [
            '3ad78e726c1ec02b7ebfe92b23d9ec34', 
            'aae5939c8efdf2f04e60b9fe7117b2c2', 
            'f031d4d74f5dcbf39daaf8ca3af6e527', 
            '96d9fd5cc4f07441727df0f33e401a36', 
            '30ccdb044646d7e1f3ccea3dca08b8c0', 
            '16ae4ce5042a67ee8e177b7c587ecc82', 
            'b6da0bb11a23855d9c5cb1b4c6412e0a', 
            'db4f1aa530967d6732ce4715eb0ee24b', 
            'a81738252621dd180a34f3455b4baa2f', 
            '77e2b508db7fd89234caf7939ee5621a', 
            'b8499c251f8442ee13f0933b688fcd19', 
            '965135f8a81f25c9d630b17502f68e53', 
            '8b87145a01ad1c6cede995ea3670454f', 
            '8eae3b10a0c8ca6d1d3b0fa61e56b0b2', 
            '64b4d629810fda6bafdf08f3b0d8d2c5', 
            'd7e5dbd3324595f8fdc7d7c571da6c2a', 
            'f3f72375264e167fca9de2c1527d9606', 
            '8ee79dd4f401ff9b7ea945d86666c13b', 
            'dd35cea2799940b40db3f819cb94c08b', 
            '6941cb6b3e08c2b7afa581ebdd607b87', 
            '2c20f439f6bb097b29b8bd6d99aad799', 
            '625d01f058e565f77ae86378bd2c49b3', 
            'c0b5fd98190ef45fbb4301438d095950', 
            '13001ff5d99806efd25da34f56be854b', 
            '3b594c60f5c8277a5113677f94208d82', 
            'e9c0fc1818e4aa46bd2e39d638f89e05', 
            'f8023ee9c3fdc45a019b4e985c7e1a54', 
            '35f40182ab4662f3023baec1ee796b57', 
            '3aebbad7303649b4194a6945c6cc3694', 
            'a2124bea53ec2834279bed7f7eb0f938', 
            'b9fb4399fa4facc7309e14ec98360b0a', 
            'c26277437420c5d634f715aea81a9132', 
            '171a0e1b2dd424f0e089af2c4c10f32f', 
            '7cadbe402d1b208fe735edce00aee7ce', 
            '43b02ff929a1485af6f5c6d6558baa0f', 
            '092faacc9bf43508bf8fa8613ca75dea', 
            'cb2bf8280f3f9742c7ed513fe802629c', 
            '215a41ee442fa992a6e323986ded3f68', 
            'f21e99cf4f0f77cea836e11a2fe75fb1', 
            '95e3a0ca9079e646331df8b4e70d2cd6', 
            '4afe7f120ce7613f74fc12a01a828073', 
            '827f000e75e2c8b9d479beed913fe678', 
            '35830c8e7aaefe2d30310ef381cbf691', 
            '191aa0f2c8570144f38657ea4085ebe5', 
            '85062c2c909f15d9269b6c18ce99c4f0', 
            '678034dc9e41b5a560ed239eeab1bc78', 
            'c2f93a4ce5ab6d5d56f1b93cf19911c1', 
            '1c3112bcb0c1dcc749d799743691bf82', 
            '00c55bd75c7f9c881989d3ec1911c0d4', 
            'ea2e6b5ef182b7dff3629abd6a12045f', 
            '22322327e01780b17397f24087f8cc6f', 
            'c9cacb5cd11692c373b2411768149ee7', 
            'a18e3dbbca577860dab6b80da3139256', 
            '79b61c37bf328ecca8d743265a3d425c', 
            'd2d99c6bcc1f06fda8e27e8ae3f1ccc7', 
            '1bfd4b91c701fd6b61b7f997829d663b', 
            '11005d52f25f16bdc9545a876a63490a', 
            '3a4d354f02bb5a5e47d39666867f246a', 
            'd451b8d6e1e1a0ebb155fbbf6e7b7dc3', 
            '6898d4f42fa7ba6a10ac05e87b9f2080', 
            'b611295e739ca7d9b50f8e4c0e754a3f', 
            '7d33fc7d8abe3ca1936759f8f5deaf20', 
            '3b5e0f566dc96c298f0c12637539b25c', 
            'f807c3e7985fe0f5a50e2cdb25c5109e', 
            '41f992a856fb278b389a62f5d274d7e9', 
            '10d3ed7a6fe15ab4d91acbc7d0767ab1', 
            '21feecd45b2e675973ac33bf0c5424fc', 
            '1480cb3955ba62d09eea668f7c708817', 
            '66404033d6b72b609354d5496e7eb511', 
            '1c317a220a7d700da2b1e075b00266e1', 
            'ab3b89542233f1271bf8fd0c0f403545', 
            'd93eae966fac46dca927d6b114fa3f9e', 
            '1bdec521316503d9d5ee65df3ea94ddf', 
            'eef456431dea8b4acf83bdae3717f75f', 
            '06f2519a2fafaa596bfef5cfa15c21b9', 
            '251a7eac7e2fe809e4aa8d0d7012531a', 
            '3bffc16e4c49b268a20f8d96a60b4058', 
            'e886f9281999c5bb3b3e8862e2f7c988', 
            '563bf90d61beef39f48dd625fcef1361', 
            '4d37c850644563c69fd0acd9a049325b', 
            'b87c921b91829ef3b13ca541ee1130a6', 
            '2e65eb6b6ea383e109accce8326b0393', 
            '9ca547f7439edc3e255c0f4d49aa8990', 
            'a5e652614c9300f37816b1f9fd0c87f9', 
            '14954f0b4697776f44494fe458d814ed', 
            '7c8d9ab6c2761723fe42f8bb506cbcf7', 
            'db7e1932679fdd99742aab04aa0d5a80', 
            '4c6a1c83e568cd10f27c2d73ded19c28', 
            '90ecbe6177e674c98de412413f7ac915', 
            '90684a2ac55fe1ec2b8ebd5622520b73', 
            '7472f9a7988607ca79707795991035e6', 
            '56aff089878bf3352f8df172a3ae47d8', 
            '65c0526cbe40161b8019a2a3171abd23', 
            '377be0be33b4e3e310b4aabda173f84f', 
            '9402e9aa6f69de6504da8d20c4fcaa2f', 
            '123c1f4af313ad8c2ce648b2e71fb6e1', 
            '1ffc626d30203dcdb0019fb80f726cf4', 
            '76da1fbe3a50728c50fd2e621b5ad885', 
            '082eb8be35f442fb52668e16a591d1d6', 
            'e656f9ecf5fe27ec3e4a73d00c282fb3', 
            '2ca8209d63274cd9a29bb74bcd77683a', 
            '79bf5dce14bb7dd73a8e3611de7ce026', 
            '3c849939a5d29399f344c4a0eca8a576', 
            'ed3c0a94d59bece98835da7aa4f07ca2', 
            '63919ed4ce10196438b6ad09d99cd795', 
            '7678f3a833f19fea95f3c6029e2bc610', 
            '3aa426831067d36b92be7c5f81c13c56', 
            '9272e2d2cdd11050998c845077a30ea0', 
            '088c4b53f5ec0ff814c19adae7f6246c', 
            '4010a5e401fdf0a0354ddbcc0d012b17', 
            'a87a385736c0a6189bd6589bd8445a93', 
            '545f2b83d9616dccf60fa9830e9cd287', 
            '4b706f7f92406352394037a6d4f4688d', 
            'b7972b3941c44b90afa7b264bfba7387', 
            '6f45732cf10881546f0fd23896d2bb60', 
            '2e3579ca15af27f64b3c955a5bfc30ba', 
            '34a2c5a91ae2aec99b7d1b5fa6780447', 
            'a4d6616bd04f87335b0e53351227a9ee', 
            '7f692b03945867d16179a8cefc83ea3f', 
            '3bd141ee84a0e6414a26e7a4f281f8a2', 
            'd1788f572d98b2b16ec5d5f3922b99bc', 
            '0833ff6f61d98a57b288e8c3586b85a6', 
            '8568261797de176bf0b43becc6285afb', 
            'f9b0fda0c4a898f5b9e6f661c4ce4d07', 
            '8ade895913685c67c5269f8aae42983e', 
            '39bde67d5c8ed8a8b1c37eb8fa9f5ac0', 
            '5c005e72c1418c44f569f2ea33ba54f3', 
            '3f5b8cc9ea855a0afa7347d23e8d664e',
        ]
        for (p, c) in zip(plaintext, ciphertext):
            c_ = bytes(a.encrypt(base64.b16decode(p, casefold=True)))
            assert c_ == base64.b16decode(c, casefold=True)



def check_ks():
        K = [0] * 11
        
        K[ 0] = base64.b16decode("86bfdd1cff68b7316babaffc0b5b74e9", casefold=True)
        K[ 1] = base64.b16decode("be2dc337414574062aeedbfa21b5af13", casefold=True)
        K[ 2] = base64.b16decode("6954beca2811cacc02ff1136234abe25", casefold=True)
        K[ 3] = base64.b16decode("bbfa81ec93eb4b2091145a16b25ee433", casefold=True)
        K[ 4] = base64.b16decode("eb9342db787809fbe96c53ed5b32b7de", casefold=True)
        K[ 5] = base64.b16decode("d83a5fe2a0425619492e05f4121cb22a", casefold=True)
        K[ 6] = base64.b16decode("640dba2bc44fec328d61e9c69f7d5bec", casefold=True)
        K[ 7] = base64.b16decode("db3474f01f7b98c2921a71040d672ae8", casefold=True)
        K[ 8] = base64.b16decode("ded1ef27c1aa77e553b006e15ed72c09", casefold=True)
        K[ 9] = base64.b16decode("cba0ee7f0a0a999a59ba9f7b076db372", casefold=True)
        K[10] = base64.b16decode("c1cdaebacbc73720927da85b95101b29", casefold=True)
        
        '''
        K[ 0] = base64.b16decode("91287ACDF26EC55982DC89D36C7111E6".lower(), casefold=True)
        K[ 1] = base64.b16decode("33AAF49DC1C431C44318B8172F69A9F1".lower(), casefold=True)
        K[ 2] = base64.b16decode("C879558809BD644C4AA5DC5B65CC75AA".lower(), casefold=True)
        K[ 3] = base64.b16decode("87E4F9C58E599D89C4FC41D2A1303478".lower(), casefold=True)
        K[ 4] = base64.b16decode("8BFC45F705A5D87EC15999AC6069ADD4".lower(), casefold=True)
        K[ 5] = base64.b16decode("62690D2767CCD559A6954CF5C6FCE121".lower(), casefold=True)
        K[ 6] = base64.b16decode("F291F093955D25CA33C8693FF534881E".lower(), casefold=True)
        K[ 7] = base64.b16decode("AA5582753F08A7BF0CC0CE80F9F4469E".lower(), casefold=True)
        K[ 8] = base64.b16decode("950F89ECAA072E53A6C7E0D35F33A64D".lower(), casefold=True)
        K[ 9] = base64.b16decode("4D2B6A23E72C447041EBA4A31ED802EE".lower(), casefold=True)
        K[10] = base64.b16decode("1A5C4251FD700621BC9BA282A243A06C".lower(), casefold=True)
        '''
        '''
        K[ 0] = base64.b16decode("B1C2B25F453E003FFEAA0F6855C7C8F1".lower(), casefold=True)
        K[ 1] = base64.b16decode("762A13A33314139CCDBE1CF49879D405".lower(), casefold=True)
        K[ 2] = base64.b16decode("C26278E5F1766B793CC8778DA4B1A388".lower(), casefold=True)
        K[ 3] = base64.b16decode("0E68BCACFF1ED7D5C3D6A058676703D0".lower(), casefold=True)
        K[ 4] = base64.b16decode("8313CC297C0D1BFCBFDBBBA4D8BCB874".lower(), casefold=True)
        K[ 5] = base64.b16decode("F67F5E488A7245B435A9FE10ED154664".lower(), casefold=True)
        K[ 6] = base64.b16decode("8F251D1D055758A930FEA6B9DDEBE0DD".lower(), casefold=True)
        K[ 7] = base64.b16decode("26C4DCDC23938475136D22CCCE86C211".lower(), casefold=True)
        K[ 8] = base64.b16decode("E2E15E57C172DA22D21FF8EE1C993AFF".lower(), casefold=True)
        K[ 9] = base64.b16decode("176148CBD61392E9040C6A07189550F8".lower(), casefold=True)
        K[10] = base64.b16decode("0B320966DD219B8FD92DF188C1B8A170".lower(), casefold=True)
        '''
        
        for r in range(10):
            assert K[r+1][3]  == K[r][3]  ^ S[K[r][12]]
            assert K[r+1][7]  == K[r][7]  ^ K[r][3]  ^ S[K[r][12]]
            assert K[r+1][11] == K[r][11] ^ K[r][7]  ^ K[r][3]  ^ S[K[r][12]]
            assert K[r+1][15] == K[r][15] ^ K[r][11] ^ K[r][7]  ^ K[r][3]  ^ S[K[r][12]]

            assert K[r+1][3]  == K[r][3]  ^ S[K[r][12]]
            assert K[r+1][7]  == K[r][7]  ^ K[r+1][3]
            assert K[r+1][11] == K[r][11] ^ K[r+1][7]
            assert K[r+1][15] == K[r][15] ^ K[r+1][11]
            assert K[r+1][2]  == K[r][2]  ^ S[K[r][15]]
            assert K[r+1][6]  == K[r][6]  ^ K[r+1][2]
            assert K[r+1][10] == K[r][10] ^ K[r+1][6]
            assert K[r+1][14] == K[r][14] ^ K[r+1][10]       
            assert K[r+1][1]  == K[r][1]  ^ S[K[r][14]]
            assert K[r+1][5]  == K[r][5]  ^ K[r+1][1]
            assert K[r+1][9]  == K[r][9]  ^ K[r+1][5]
            assert K[r+1][13] == K[r][13] ^ K[r+1][9]
            assert K[r+1][0]  == K[r][0]  ^ S[K[r][13]] ^ RCON[r]
            assert K[r+1][4]  == K[r][4]  ^ K[r+1][0]
            assert K[r+1][8]  == K[r][8]  ^ K[r+1][4]
            assert K[r+1][12] == K[r][12] ^ K[r+1][8]

        a = AES(K[0])
        subkeys = [b''.join([a.subkeys[r][i] for i in range(4)]) for r in range(11)]
        for i in range(11):
            assert K[i] == subkeys[i]
        return subkeys

if __name__ == '__main__':
    
    '''
    assert set(enum(0)) == set(range(256))
    assert set(enum(170)) == set(range(256))
    test_vectors()
    '''
    #print(check_ks())
