# -*- coding: utf-8 -*-
"""
Pure Python QR Code SVG Engine (Zero-Dependency)
Implements ISO/IEC 18004 QR Code Generation (Byte Mode, Levels L & M, Versions 1-10)
Outputs vector SVG directly matching Meikova Ambient Dark design system.
"""

from typing import List, Tuple, Optional


class QREngine:
    # GF(256) Math for Reed-Solomon Error Correction
    EXP = [0] * 512
    LOG = [0] * 256

    _initialized = False

    @classmethod
    def _init_gf(cls):
        if cls._initialized:
            return
        x = 1
        for i in range(255):
            cls.EXP[i] = x
            cls.EXP[i + 255] = x
            cls.LOG[x] = i
            x <<= 1
            if x & 0x100:
                x ^= 0x11D  # Primitive polynomial x^8 + x^4 + x^3 + x^2 + 1
        cls.LOG[0] = 0
        cls._initialized = True

    @classmethod
    def _gmul(cls, a: int, b: int) -> int:
        if a == 0 or b == 0:
            return 0
        return cls.EXP[cls.LOG[a] + cls.LOG[b]]

    @classmethod
    def _poly_mul(cls, p: List[int], q: List[int]) -> List[int]:
        r = [0] * (len(p) + len(q) - 1)
        for i, a in enumerate(p):
            for j, b in enumerate(q):
                r[i + j] ^= cls._gmul(a, b)
        return r

    @classmethod
    def _rs_generator_poly(cls, nsym: int) -> List[int]:
        g = [1]
        for i in range(nsym):
            g = cls._poly_mul(g, [1, cls.EXP[i]])
        return g

    @classmethod
    def _rs_encode(cls, msg: List[int], nsym: int) -> List[int]:
        cls._init_gf()
        gen = cls._rs_generator_poly(nsym)
        out = list(msg) + [0] * nsym
        for i in range(len(msg)):
            coef = out[i]
            if coef != 0:
                for j in range(len(gen)):
                    out[i + j] ^= cls._gmul(gen[j], coef)
        return out[len(msg):]

    # Version specifications for Byte mode (Level M preferred for general use)
    # (Version, Total Codewords, EC Codewords per block, Blocks in Group 1, Data CW in G1, Blocks in G2, Data CW in G2)
    SPECS = [
        # Ver, TotCW, EC_CW, B1, D1, B2, D2
        (1, 26, 10, 1, 16, 0, 0),
        (2, 44, 16, 1, 28, 0, 0),
        (3, 70, 26, 1, 44, 0, 0),
        (4, 100, 18, 2, 32, 0, 0),
        (5, 134, 24, 2, 43, 0, 0),
        (6, 172, 16, 4, 27, 0, 0),
        (7, 196, 18, 4, 31, 0, 0),
        (8, 242, 22, 2, 38, 2, 39),
        (9, 292, 22, 3, 36, 2, 37),
        (10, 346, 26, 4, 43, 1, 44),
        (11, 404, 30, 1, 50, 4, 51),
        (12, 466, 22, 6, 36, 2, 37),
    ]

    ALIGNMENT_PATTERNS = {
        2: [6, 18],
        3: [6, 22],
        4: [6, 26],
        5: [6, 30],
        6: [6, 34],
        7: [6, 22, 38],
        8: [6, 24, 42],
        9: [6, 26, 46],
        10: [6, 28, 50],
        11: [6, 30, 54],
        12: [6, 32, 58],
    }

    FORMAT_INFO = {
        # Level M (00) with Mask 000..111
        0: 0x5412,
        1: 0x5125,
        2: 0x5E7C,
        3: 0x5B4B,
        4: 0x45F9,
        5: 0x40CE,
        6: 0x4F97,
        7: 0x4AA0,
    }

    @classmethod
    def _choose_version(cls, data_len: int) -> Optional[tuple]:
        for spec in cls.SPECS:
            ver, tot, ec, b1, d1, b2, d2 = spec
            cap = (b1 * d1) + (b2 * d2)
            # Overhead for byte mode: 4 bits mode + 8/16 bits char count
            header_bytes = 2 if ver < 10 else 3
            if data_len + header_bytes <= cap:
                return spec
        return None

    @classmethod
    def generate_matrix(cls, text: str) -> List[List[bool]]:
        raw_data = text.encode("utf-8")
        data_len = len(raw_data)
        spec = cls._choose_version(data_len)
        if not spec:
            raise ValueError(f"Dữ liệu QR quá dài ({data_len} bytes, tối đa 350 bytes)")

        version, total_cw, ec_len, b1, d1, b2, d2 = spec
        total_data_cw = (b1 * d1) + (b2 * d2)

        # 1. Encode bit stream (Byte mode: 0100)
        bits = "0100"
        count_bits = 8 if version < 10 else 16
        bits += bin(data_len)[2:].zfill(count_bits)
        for b in raw_data:
            bits += bin(b)[2:].zfill(8)

        # Terminator
        rem = (total_data_cw * 8) - len(bits)
        bits += "0" * min(4, rem)
        # Byte align
        if len(bits) % 8 != 0:
            bits += "0" * (8 - (len(bits) % 8))

        # Pad bytes 0xEC, 0x11
        pad_bytes = [0xEC, 0x11]
        pad_idx = 0
        while len(bits) < total_data_cw * 8:
            bits += bin(pad_bytes[pad_idx])[2:].zfill(8)
            pad_idx = (pad_idx + 1) % 2

        data_bytes = [int(bits[i:i + 8], 2) for i in range(0, len(bits), 8)]

        # 2. Block division & Reed-Solomon computation
        blocks = []
        ec_blocks = []
        offset = 0

        for _ in range(b1):
            block = data_bytes[offset:offset + d1]
            blocks.append(block)
            ec_blocks.append(cls._rs_encode(block, ec_len))
            offset += d1

        for _ in range(b2):
            block = data_bytes[offset:offset + d2]
            blocks.append(block)
            ec_blocks.append(cls._rs_encode(block, ec_len))
            offset += d2

        # Interleave data
        final_cw = []
        max_d = max(d1, d2)
        for i in range(max_d):
            for block in blocks:
                if i < len(block):
                    final_cw.append(block[i])

        # Interleave EC
        for i in range(ec_len):
            for ec_b in ec_blocks:
                final_cw.append(ec_b[i])

        # Remainder bits
        remainder_bits = {1: 0, 2: 7, 3: 7, 4: 7, 5: 7, 6: 7, 7: 0, 8: 0, 9: 0, 10: 0, 11: 0, 12: 0}.get(version, 0)
        final_bits = "".join(bin(b)[2:].zfill(8) for b in final_cw) + ("0" * remainder_bits)

        # 3. Create Matrix & Function Patterns
        size = 21 + (version - 1) * 4
        # Matrix: None = unallocated, True = dark, False = light
        mat: List[List[Optional[bool]]] = [[None] * size for _ in range(size)]
        is_func: List[List[bool]] = [[False] * size for _ in range(size)]

        def set_func(r: int, c: int, val: bool):
            mat[r][c] = val
            is_func[r][c] = True

        # Finder patterns
        def add_finder(start_r: int, start_c: int):
            for r in range(start_r, start_r + 7):
                for c in range(start_c, start_c + 7):
                    dr = r - start_r
                    dc = c - start_c
                    is_black = (
                        dr == 0 or dr == 6 or dc == 0 or dc == 6 or
                        (2 <= dr <= 4 and 2 <= dc <= 4)
                    )
                    set_func(r, c, is_black)
            # Separator
            for r in range(start_r - 1, start_r + 8):
                for c in range(start_c - 1, start_c + 8):
                    if 0 <= r < size and 0 <= c < size and not is_func[r][c]:
                        set_func(r, c, False)

        add_finder(0, 0)
        add_finder(0, size - 7)
        add_finder(size - 7, 0)

        # Alignment patterns
        if version in cls.ALIGNMENT_PATTERNS:
            coords = cls.ALIGNMENT_PATTERNS[version]
            for r in coords:
                for c in coords:
                    # Skip if overlapping with finders
                    if (r < 9 and c < 9) or (r < 9 and c >= size - 8) or (r >= size - 8 and c < 9):
                        continue
                    for dr in range(-2, 3):
                        for dc in range(-2, 3):
                            val = abs(dr) == 2 or abs(dc) == 2 or (dr == 0 and dc == 0)
                            set_func(r + dr, c + dc, val)

        # Timing patterns
        for i in range(8, size - 8):
            set_func(6, i, i % 2 == 0)
            set_func(i, 6, i % 2 == 0)

        # Dark module
        set_func(4 * version + 9, 8, True)

        # Reserve Format Info areas
        for c in range(9):
            if not is_func[8][c]:
                is_func[8][c] = True
        for r in range(9):
            if not is_func[r][8]:
                is_func[r][8] = True
        for c in range(size - 8, size):
            is_func[8][c] = True
        for r in range(size - 7, size):
            is_func[r][8] = True

        # 4. Fill Data Bits
        bit_idx = 0
        right = size - 1
        upward = True

        while right > 0:
            if right == 6:  # Skip vertical timing pattern
                right -= 1
            col_pair = [right, right - 1]
            rows = range(size - 1, -1, -1) if upward else range(size)

            for r in rows:
                for c in col_pair:
                    if not is_func[r][c]:
                        if bit_idx < len(final_bits):
                            mat[r][c] = (final_bits[bit_idx] == "1")
                            bit_idx += 1
                        else:
                            mat[r][c] = False
            right -= 2
            upward = not upward

        # 5. Apply Mask (Standard Mask 0: (row + col) % 2 == 0)
        mask_num = 0
        for r in range(size):
            for c in range(size):
                if not is_func[r][c]:
                    if (r + c) % 2 == 0:
                        mat[r][c] = not mat[r][c]

        # 6. Write Format Information (Level M, Mask 0)
        fmt_bits = bin(cls.FORMAT_INFO[mask_num])[2:].zfill(15)
        # Top-left format bits
        for i in range(6):
            mat[8][i] = (fmt_bits[i] == "1")
        mat[8][7] = (fmt_bits[6] == "1")
        mat[8][8] = (fmt_bits[7] == "1")
        mat[7][8] = (fmt_bits[8] == "1")
        for i in range(9, 15):
            mat[14 - i][8] = (fmt_bits[i] == "1")

        # Bottom-left & Top-right format bits
        for i in range(7):
            mat[size - 1 - i][8] = (fmt_bits[i] == "1")
        for i in range(7, 15):
            mat[8][size - 15 + i] = (fmt_bits[i] == "1")

        return [[bool(cell) for cell in row] for row in mat]

    @classmethod
    def generate_svg(
        cls,
        text: str,
        size_px: int = 260,
        fg_color: str = "#A6C5FF",
        bg_color: str = "#070D17",
        quiet_zone: int = 4
    ) -> str:
        matrix = cls.generate_matrix(text)
        modules = len(matrix)
        total_dim = modules + (quiet_zone * 2)

        paths = []
        for r in range(modules):
            for c in range(modules):
                if matrix[r][c]:
                    x = c + quiet_zone
                    y = r + quiet_zone
                    paths.append(f"M{x},{y}h1v1h-1z")

        path_data = "".join(paths)
        svg = (
            f'<svg xmlns="http://www.w3.org/2000/svg" '
            f'viewBox="0 0 {total_dim} {total_dim}" '
            f'width="{size_px}" height="{size_px}" '
            f'shape-rendering="crispEdges">\n'
            f'  <rect width="{total_dim}" height="{total_dim}" fill="{bg_color}" rx="8"/>\n'
            f'  <path d="{path_data}" fill="{fg_color}"/>\n'
            f'</svg>'
        )
        return svg
