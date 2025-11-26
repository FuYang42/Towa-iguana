# Iguana芯片寄存器数据分析工具

从PCAP文件中提取并分析12个Iguana芯片的寄存器数据，支持单文件一致性检测和双文件对比分析。

## 数据结构

- 目标数据包：738字节
- 分析数据：最后192字节
- 12个芯片 × 4个寄存器 × 4字节(32位)

## 安装

```bash
pip install -r requirements.txt
```

## 使用

### 模式1：单文件分析（一致性检测）

分析单个PCAP文件中的寄存器数据一致性：

```bash
python iguana_analyzer.py <PCAP文件路径>
```

示例：
```bash
python iguana_analyzer.py test_tool.pcap
python iguana_analyzer.py C:\Users\FuYou\Desktop\data.pcap
```

### 模式2：双文件对比分析（NEW）

对比两个PCAP文件中的寄存器数据差异：

```bash
python iguana_analyzer.py <第一个PCAP文件> <第二个PCAP文件>
```

示例：
```bash
python iguana_analyzer.py before.pcap after.pcap
python iguana_analyzer.py file1.pcap file2.pcap
```

## 功能

### 单文件分析模式
1. 提取738字节数据包的最后192字节
2. 反转每个寄存器的字节序
3. 转换为二进制格式
4. 对比所有数据包，检测寄存器值一致性
5. 跨芯片对比相同寄存器的值
6. 自动导出Excel表格（包含ChipID、RegID、十六进制值、二进制值）

### 双文件对比模式（NEW）
1. 同时读取两个PCAP文件
2. 提取并解析两个文件的寄存器数据
3. 逐个芯片、逐个寄存器对比两个文件的数据
4. 显示差异位的详细信息
5. 生成汇总统计报告
6. 自动导出Excel对比表格（包含两个文件的值和差异状态，差异行高亮显示）

## 输出示例

### 单文件分析模式输出

```
CHIP 0 Reg0  ✓  0x356A55AA  00110101011010100101010110101010
CHIP 0 Reg1  ✓  0xF0F0F0F0  11110000111100001111000011110000
CHIP 0 Reg2  ✗  Inconsistent!
            Value1 (8x): 0x12345678  00010010001101000101011001111000  Packets[1, 2, 3, 4, 5, 6, 7, 8]
            Value2 (2x): 0x87654321  10000111011001010100001100100001  Packets[9, 10]
```

### 双文件对比模式输出

```
================================================================================
DUAL FILE COMPARISON MODE
================================================================================

[FILE 1: before.pcap]
Reading PCAP file: before.pcap
Found 10 packets of 738 bytes, extracted 10 register data sets

[FILE 2: after.pcap]
Reading PCAP file: after.pcap
Found 10 packets of 738 bytes, extracted 10 register data sets

Parsing register data from both files...

================================================================================
REGISTER VALUE COMPARISON BETWEEN TWO FILES
================================================================================

CHIP 0  ✓  All registers identical

CHIP 1  ✗  Differences found:
  Reg2:
    File1: 0x12345678  00010010001101000101011001111000
    File2: 0x87654321  10000111011001010100001100100001
    Diff at bits: [0, 1, 2, 3, 5, 7, 8, ...] (total: 16 bits)

CHIP 2  ✓  All registers identical

...

================================================================================
COMPARISON SUMMARY
================================================================================
Total registers compared: 48
Identical registers: 46
Different registers: 2

✗ Found differences in 4.2% of registers
================================================================================
```

## Excel导出功能

### 单文件分析模式
运行后会自动生成Excel文件：`<文件名>_analysis.xlsx`

**Excel表格结构：**
| ChipID | RegID | Value (Hex) | Value (Binary) |
|--------|-------|-------------|----------------|
| 0      | 0     | 0x356A55AA  | 00110101011010100101010110101010 |
| 0      | 1     | 0xF0F0F0F0  | 11110000111100001111000011110000 |
| ...    | ...   | ...         | ... |

### 双文件对比模式
运行后会自动生成Excel文件：`<文件1名>_vs_<文件2名>_comparison.xlsx`

**Excel表格结构：**（列标题会使用实际的文件名）
| ChipID | RegID | abnormal (Hex) | abnormal (Binary) | normal (Hex) | normal (Binary) | Status |
|--------|-------|----------------|-------------------|--------------|-----------------|--------|
| 0      | 0     | 0x00000018     | 00000000...       | 0x00000018   | 00000000...     | Identical |
| 4      | 1     | 0x0147E000     | 00000001...       | 0x0047E000   | 00000000...     | Different |

**特点：**
- 表头使用蓝色背景，白色粗体字
- 差异行使用黄色高亮显示，方便快速识别
- 自动调整列宽以适应内容
