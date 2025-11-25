# Iguana芯片寄存器数据分析工具

从PCAP文件中提取并分析12个Iguana芯片的寄存器数据，检测数据一致性。

## 数据结构

- 目标数据包：738字节
- 分析数据：最后192字节
- 12个芯片 × 4个寄存器 × 4字节(32位)

## 安装

```bash
pip install -r requirements.txt
```

## 使用

```bash
python iguana_analyzer.py <PCAP文件路径>
```

示例：
```bash
python iguana_analyzer.py test_tool.pcap
python iguana_analyzer.py C:\Users\FuYou\Desktop\data.pcap
```

## 功能

1. 提取738字节数据包的最后192字节
2. 反转每个寄存器的字节序
3. 转换为二进制格式
4. 对比所有数据包，检测寄存器值一致性

## 输出示例

```
CHIP 0 Reg0  ✓  0x356A55AA  00110101011010100101010110101010
CHIP 0 Reg1  ✓  0xF0F0F0F0  11110000111100001111000011110000
CHIP 0 Reg2  ✗  Inconsistent!
            Value1 (8x): 0x12345678  00010010001101000101011001111000  Packets[1, 2, 3, 4, 5, 6, 7, 8]
            Value2 (2x): 0x87654321  10000111011001010100001100100001  Packets[9, 10]
```
