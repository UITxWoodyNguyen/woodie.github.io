---
title: "Vernichtet - Dreamhack Wargame Write up"
date: 2026-03-05
categories: [CTF, Training]
tags: [Dreamhack, reverse]
description: "This is a Reverse Engineering challenge from Dreamhack CTF"
---

> Problem Link: https://dreamhack.io/wargame/challenges/2343

## Analyzing
### Phân tích hành vi từ file gốc
- Đề cho một file binary và nhiệm vụ của user là tìm Snake Path trên ma trận 15x15. Kiểm tra bằng command `file`, ta nhận thấy đây là một file ELF 64-bit đã được strip. Chạy thử để phân tích hành vi của file, ta có được kết quả sau:
    ```bash
    $ ./main
    Usage ./main <answer file>
    ```
- Điều này có nghĩa ta cần có một file answer để chạy file binary này. Tạo random một file `test.txt`, ta có được kết quả như sau:
    ```bash
    $ echo "test" > test.txt
    $ ./main test.txt
    Wrong answer.
    ```
- Sử dụng `ltrace` để thu thập thêm thông tin, ta có kết quả sau:
    ```bash
    $ ltrace ./main test.txt
    fopen("test.txt", "rb")                                                                = 0x5aafe9a2e2a0
    fseek(0x5aafe9a2e2a0, 0, 2, 0x77d82851b1a5)                                            = 0
    ftell(0x5aafe9a2e2a0, 0x5aafe9a2e480, 0, 4)                                            = 4 // check file size
    rewind(0x5aafe9a2e2a0, 0, 0, 0)                                                        = 0
    puts("Wrong answer."Wrong answer.
    )                                                                  = 14
    +++ exited (status 0) +++
    ```
- Từ đây, ta nhận xét thấy file binary sẽ thực hiện kiểm tra kích thước file trước khi đọc nội dung.

### Find out Anti-Disassembling
- Thực hiện decompile file với IDA, ta phát hiện nhiều đoạn mã assembly có dạng như sau:
    ```asm
    .text:0000000000001271 loc_1271:                               ; CODE XREF: .text:loc_1271↑j
    .text:0000000000001271                 jmp     short near ptr loc_1271+1
    .text:0000000000001271 ; ---------------------------------------------------------------------------
    .text:0000000000001273                 db 0C1h, 0FFh, 0C9h, 48h, 89h
    .text:0000000000001278                 dq 0FC45C7E87Dh, 0FFEB000000F4E900h, 6348FC458BC9FFC1h
    .text:0000000000001290                 dq 48C00148D08948D0h, 48C9FFC1FFEBC201h, 0FFEB00002D7C058Dh
    .text:00000000000012A8                 dq 0EB0204B60FC9FFC1h, 840FC084C9FFC1FFh, 0EBFC458B000000AFh
    .text:00000000000012C0                 dq 48D06348C9FFC1FFh, 48C9FFC1FFEBD089h, 58D48C20148C001h
    .text:00000000000012D8                 dq 204B60F00002D45h, 0C9FFC1FFEBD0B60Fh, 0C1FFEB04E0C1D089h
    .text:00000000000012F0                 dq 458BC689D029C9FFh, 6348C9FFC1FFEBFCh, 0FFC1FFEBD08948D0h
    .text:0000000000001308                 dq 48C20148C00148C9h, 0B60F00002D0A058Dh, 0FC9FFC1FFEB0204h
    .text:0000000000001320                 dq 48D06348F001C0B6h, 0FFEBD00148E8458Bh, 458B30B60FC9FFC1h
    .text:0000000000001338                 dq 48D08948D06348FCh, 58D48C20148C001h, 204B60F00002CD6h
    .text:0000000000001350                 dq 0C63840C9FFC1FFEBh, 0EB00000000B81C74h, 0FFEB26EBC9FFC1FFh
    .text:0000000000001368                 dq 0C9FFC1FFEBC9FFC1h, 4583C9FFC1FFEB90h, 0E0FC7D8101FCh
    .text:0000000000001380                 dq 0B8FFFFFF048E0F00h
    .text:0000000000001388                 db 1, 3 dup(0), 5Dh, 0C3h
    .text:0000000000001388 ; } // starts at 1269
    ```
- **Nhận xét**: Các đoạn mã này bị làm xáo trộn (ofuscate) với pattern:
    ```asm
    loc_1271:
    jmp     short near ptr loc_1271+1
    db      0C1h, 0FFh, 0C9h, 48h, 89h
    ```
- **Nhận xét**:
    - `jmp short near ptr loc_1271+1` = nhảy đến địa chỉ 0x1271 + 1 = 0x1272
    - Opcode encoded: `eb ff` (`eb` = `jmp short`, `ff` = `offset -1` vì -1 tính từ sau instruction = +1 từ đầu)
    - Khi CPU nhảy đến `0x1272`, nó đọc bytes `ff c1 ff c9`:
        - ff c1 = inc ecx
        - ff c9 = dec ecx
    - IDA thấy jmp +1 nên hiểu sai flow, dump raw bytes thay vì decode đúng
    - Có 3 address trong đoạn mã assembly được decompile từ IDA có pattern này bao gồm `0x1271`, `0x139a` và `0x1604`.
- Đây là kĩ thuật **jmp into middle of instruction**. Cụ thể trong case này:
    - `eb ff` = `jmp -1` (nhảy vào giữa instruction)
    - `c1 ff c9` = `ror ecx, 0xc9` hoặc được hiểu khác tùy context
    - Thực tế `ff c1` = `inc ecx` và `ff c9` = `dec ecx` (NOP equivalent)
- Khi đó **Obfuscation Pattern** trong trường hợp này là `eb ff c1 ff c9` (5 bytes)

### Create Deobfuscate Binary file
- Từ Obfuscation Pattern tìm được ở trên, ta thực hiện patch tất cả các pattern thành NOP (`90, 90, 90, 90, 90`). Script cụ thể:
    ```python
    #!/usr/bin/env python3
    # deobfuscate.py - Patch anti-disassembly patterns

    with open('main', 'rb') as f:
        data = bytearray(f.read())

    # Pattern: eb ff c1 ff c9
    # - eb ff    = jmp short $-1 (nhảy vào byte ff)
    # - ff c1    = inc ecx
    # - ff c9    = dec ecx
    # Thực tế chỉ là NOP vì inc rồi dec lại
    pattern = bytes([0xeb, 0xff, 0xc1, 0xff, 0xc9])
    nops = bytes([0x90, 0x90, 0x90, 0x90, 0x90])

    i = 0
    count = 0
    while i < len(data) - 4:
        if data[i:i+5] == pattern:
            data[i:i+5] = nops
            count += 1
            i += 5
        else:
            i += 1

    print(f"Patched {count} patterns")

    with open('main_deobf', 'wb') as f:
        f.write(data)

    print("Written main_deobf")
    ```
- Sau khi tạo xong file Deobfuscation, thực hiện đối chiếu lại với binary gốc:
    ```bash
    $ ls -la main main_deobf
    -rwxrwxrwx 1 nmt nmt 15160 Apr 30  2025 main
    -rwxrwxrwx 1 nmt nmt 15160 Feb 10 20:02 main_deobf
    ```
- Size của 2 file là như nhau, tiếp tục kiểm tra xem file mới có hoạt động hay không:
    ```bash
    $ chmod +x main_deobf
    $ ./main_deobf test.txt
    Wrong answer.   
    ```
- File vẫn hoạt động bình thường, tiếp tục kiểm tra difference hex:
    ```bash
    $ xxd main | head -100 > main.hex
    $ xxd main_deobf | head -100 > main_deobf.hex
    $ diff main.hex main_deobf.hex | head -20
    ```
- Kết quả trả ra không có difference giữa 2 file, điều đó chứng tỏ file Deobfuscate Binary hoàn toàn đúng.

### Re-Disassembly Deobfuscate Binary File
- Sau khi có được Deobfuscate Binary File, thực hiện disassembly lại một lần nữa theo địa chỉ lấy từ IDA. Ta có kết quả như sau:
    - `main()` - `address = 0x15f5`:
        ```bash
        $ objdump -d -M intel main_deobf > main_deobf.asm
        $ objdump -d -M intel main_deobf | grep -A200 "15f5:"
        15f5:	f3 0f 1e fa          	endbr64
        15f9:	55                   	push   rbp
        15fa:	48 89 e5             	mov    rbp,rsp
       
        ...
        ```
    > Read more in [main.asm](https://github.com/UITxWoodyNguyen/CTF/blob/main/Dreamhack/Vernichtet/main.asm)

    - Hàm Validate 1 - `address = 0x1269`:
        ```bash
        $ objdump -d -M intel main_deobf | grep -A100 "1269:"
        1269:	f3 0f 1e fa          	endbr64
        126d:	55                   	push   rbp
        126e:	48 89 e5             	mov    rbp,rsp
        
        ...
        ```
    > Read more in [validate-1.asm](https://github.com/UITxWoodyNguyen/CTF/blob/main/Dreamhack/Vernichtet/validate-1.asm)
    
    - Hàm Validate 2 - `address = 0x138e`:
        ```bash
        $ objdump -d -M intel main_deobf | grep -A250 "138e:"
        138e:	f3 0f 1e fa          	endbr64
        1392:	55                   	push   rbp
        1393:	48 89 e5             	mov    rbp,rsp
        1396:	48 89 7d d8          	mov    QWORD PTR [rbp-0x28],rdi
        
        ...
        ```
    > Read more in [validate-2.asm](https://github.com/UITxWoodyNguyen/CTF/blob/main/Dreamhack/Vernichtet/validate-2.asm)
- Từ đây, ta có được flow của 3 hàm này như sau:
    - `main()`:
        ```c++
        int main(int argc, char** argv) {
            FILE* fp;
            char* buffer;
            long file_size;
            char command[512];

            if (argc < 2) {
                print_usage(argv[0]);
                return 1;
            }

            // Attempt to open the provided answer file
            fp = fopen(argv[1], "rb");
            if (fp == NULL) {
                puts("File Not Found");
                return 1;
            }

            // Get file size
            fseek(fp, 0, SEEK_END);
            file_size = ftell(fp);
            rewind(fp);

            // Allocate memory and read file
            buffer = (char*)malloc(file_size + 1);
            if (fread(buffer, 1, file_size, fp) != file_size) {
                puts("Fread failed");
                free(buffer);
                fclose(fp);
                return 1;
            }
            buffer[file_size] = '\0';
            fclose(fp);

            /* The assembly contains a complex data block starting at 0x4020.
            This looks like a custom VM or a obfuscated state machine that 
            eventually triggers a hash check. 
            The command string at 0x2050 is: 
            "bash -c \"echo DH{$(sha256sum '%s' | awk '{print $1}')}\""
            */

            // Reconstructing the logic of the string formatting at 0x1170 and system call at 0x1110:
            sprintf(command, "bash -c \"echo DH{$(sha256sum '%s' | awk '{print $1}')}\"", argv[1]);
            
            // In the real binary, it compares the result of the file processing
            // against the internal expected value.
            
            // If the check passes:
            puts("Correct!");
            
            // If it fails:
            // puts("Wrong answer.");

            free(buffer);
            return 0;
        }
        ```
    - Validation 1:
        ```c++
        for (int i = 0; i < 0xe0; i++) {
            int col = table[i*3];      // offset 0x4020
            int row = table[i*3 + 1];  // offset 0x4021
            int expected = table[i*3 + 2]; // offset 0x4022
            
            if (expected == 0) break;  // Terminator
            
            int pos = col + row * 15;
            if (input[pos] != expected)
                return 0;
        }
        return 1;
        ```
    - Validation 2:
        ```c++
        // Tìm vị trí của giá trị 1
        for (row = 0; row <= 14; row++) {
            for (col = 0; col <= 14; col++) {
                if (input[col + row*15] == 1) {
                    start_col = col;
                    start_row = row;
                }
            }
        }

        // Kiểm tra path từ 1 đến 225
        for (val = 1; val < 225; val++) {
            // Tìm val+1 trong các ô lân cận 8 hướng
            found = false;
            for each neighbor of (current_col, current_row):
                if (input[neighbor] == val + 1):
                    found = true;
                    move to neighbor;
                    break;
            if (!found) return 0;
        }
        return 1;
        ```

### Get Table Constraints
- Source code lấy Table:
    ```python
    with open('main', 'rb') as f:
        f.seek(0x3020)
        table_data = f.read(450)

    for i in range(150):
        col = table_data[i*3]
        row = table_data[i*3 + 1]
        expected = table_data[i*3 + 2]
        if expected == 0:
            break
        pos = col + row * 15
        print(f"pos {pos} (col={col}, row={row}) = {expected}")
    ```

### Finding Snake Path
#### Thuật toán
**Bài toán:**
- Lưới 15x15 = 225 ô
- 150 ô có giá trị cố định (từ table)
- 75 ô trống cần điền
- Các giá trị 1-225 phải tạo thành đường đi liên tục (8 hướng adjacent)

**Thuật toán: Backtracking**

1. Parse table để biết giá trị nào ở vị trí nào
2. Tìm các "gaps" - khoảng trống giữa các giá trị liên tiếp
3. Với mỗi gap (v1 → v2), tìm đường đi từ pos(v1) đến pos(v2) qua các ô trống
4. Dùng backtracking để thử các đường đi khả thi

#### Source code:
- Ta có code backtracking như sau:
    ```python
        def solve_all_gaps(gap_idx, solution, filled):
        if gap_idx >= len(gaps):
            return True  # Solved!
        
        v1, v2, missing = gaps[gap_idx]
        p1, p2 = exp_to_pos[v1], exp_to_pos[v2]
        
        # Tìm tất cả đường đi có độ dài đúng
        for path in find_paths(p1, p2, len(missing) + 1):
            # Thử path này
            for i, p in enumerate(path):
                solution[p] = missing[i]
                filled.add(p)
            
            if solve_all_gaps(gap_idx + 1, solution, filled):
                return True
            
            # Backtrack
            for p in path:
                solution[p] = 0
                filled.remove(p)
        
        return False
    ```

### Reversing
- Từ phân tích trên, ta có source code sau:
    ```python
    #!/usr/bin/env python3
    def solve():
        # Read table from binary
        with open('main', 'rb') as f:
            f.seek(0x3020)  # Table at 0x4020 - 0x1000 (PIE offset)
            table_data = f.read(450)

        # Parse constraints from table
        exp_to_pos = {}
        pos_to_exp = {}
        for i in range(150):
            col = table_data[i*3]
            row = table_data[i*3 + 1]
            expected = table_data[i*3 + 2]
            if expected == 0:
                break
            pos = col + row * 15
            exp_to_pos[expected] = pos
            pos_to_exp[pos] = expected

        def get_neighbors(pos):
            """Get 8-way adjacent positions"""
            col = pos % 15
            row = pos // 15
            return [pos+dc+dr*15 for dc in [-1,0,1] for dr in [-1,0,1] 
                    if (dc != 0 or dr != 0) and 0 <= col+dc < 15 and 0 <= row+dr < 15]

        # Find all gaps (missing values between defined ones)
        gaps = []
        sorted_vals = sorted(exp_to_pos.keys())
        for i in range(len(sorted_vals) - 1):
            v1, v2 = sorted_vals[i], sorted_vals[i+1]
            if v2 - v1 > 1:
                gaps.append((v1, v2, list(range(v1+1, v2))))

        print(f"Table has {len(pos_to_exp)} fixed values")
        print(f"Found {len(gaps)} gaps with {sum(len(g[2]) for g in gaps)} missing values")

        # Backtracking solver
        def solve_all_gaps(gap_idx, solution, filled):
            if gap_idx >= len(gaps):
                return True
            
            v1, v2, missing = gaps[gap_idx]
            p1 = exp_to_pos[v1]
            p2 = exp_to_pos[v2]
            
            def find_paths(current, end, steps_left, path):
                """Generator for all valid paths of exact length"""
                if steps_left == 1:
                    if end in get_neighbors(current):
                        yield path
                    return
                
                for npos in get_neighbors(current):
                    if npos == end or npos in filled or npos in path:
                        continue
                    yield from find_paths(npos, end, steps_left - 1, path + [npos])
            
            steps = len(missing) + 1
            for path in find_paths(p1, p2, steps, []):
                if len(path) != len(missing):
                    continue
                
                # Try this path
                for i, p in enumerate(path):
                    solution[p] = missing[i]
                    filled.add(p)
                
                if solve_all_gaps(gap_idx + 1, solution, filled):
                    return True
                
                # Backtrack
                for p in path:
                    solution[p] = 0
                    filled.remove(p)
            
            return False

        # Initialize with fixed values
        solution = [0] * 225
        filled = set()
        for pos, val in pos_to_exp.items():
            solution[pos] = val
            filled.add(pos)

        # Solve
        if solve_all_gaps(0, solution, filled):
            print("Solution found!")
            
            # Verify
            val_to_pos = {v: i for i, v in enumerate(solution)}
            errors = sum(1 for v in range(1, 225) 
                        if val_to_pos.get(v+1) not in get_neighbors(val_to_pos.get(v, -1)))
            print(f"Verification errors: {errors}")
            
            # Write solution
            with open('answer.bin', 'wb') as f:
                f.write(bytes(solution))
            print("Written answer.bin")
            print("\nRun: ./main answer.bin")
        else:
            print("No solution found!")

    if __name__ == "__main__":
        solve()
    ```

- Sau khi chạy source để tạo `answer.bin`, thực hiện chạy file theo cú pháp ban đầu để lấy flag:
    ```bash
    ./main answer.bin
    Correct!
    DH{e309147b588c517bb4100064d6185e5430ebad23d83e601327c4907bb0232292}
    ```

### Conclusion

| Kỹ thuật | Mô tả |
|----------|-------|
| Anti-disassembly | Pattern `eb ff c1 ff c9` làm IDA hiểu sai code flow |
| Stripped binary | Không có symbol, khó trace function |
| Two-stage validation | Kiểm tra table constraints + snake path connectivity |
| Snake path puzzle | Bài toán pathfinding trên lưới với constraints |