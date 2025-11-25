#!/usr/bin/env python3
"""
Iguana芯片寄存器数据分析工具
从PCAP文件中提取并分析12个Iguana芯片的寄存器数据
"""

from scapy.all import rdpcap
import sys
from collections import defaultdict


class IguanaRegisterAnalyzer:
    """Iguana芯片寄存器数据分析器"""

    NUM_CHIPS = 12
    REGISTERS_PER_CHIP = 4
    BYTES_PER_REGISTER = 4
    BYTES_PER_CHIP = REGISTERS_PER_CHIP * BYTES_PER_REGISTER  # 16字节
    TOTAL_DATA_SIZE = NUM_CHIPS * BYTES_PER_CHIP  # 192字节
    TARGET_PACKET_LENGTH = 738

    def __init__(self, pcap_file):
        """
        初始化分析器

        Args:
            pcap_file: PCAP文件路径
        """
        self.pcap_file = pcap_file
        self.packets_data = []  # 存储所有提取的192字节数据
        self.register_values = defaultdict(list)  # {(chip_id, reg_id): [values...]}

    def extract_packets(self):
        """从PCAP文件中提取长度为738字节的数据包"""
        print(f"Reading PCAP file: {self.pcap_file}")
        try:
            packets = rdpcap(self.pcap_file)
        except Exception as e:
            print(f"Error: Unable to read PCAP file - {e}")
            sys.exit(1)

        # 筛选长度为738的数据包
        filtered_count = 0
        for pkt in packets:
            if len(pkt) == self.TARGET_PACKET_LENGTH:
                # 提取最后192字节
                raw_data = bytes(pkt)
                iguana_data = raw_data[-self.TOTAL_DATA_SIZE:]
                self.packets_data.append(iguana_data)
                filtered_count += 1

        print(f"Found {filtered_count} packets of 738 bytes, extracted {filtered_count} register data sets\n")
        return filtered_count

    def reverse_bytes(self, data):
        """
        反转字节序（小端转大端或大端转小端）

        Args:
            data: 4字节的bytes对象

        Returns:
            bytes: 反转后的字节序
        """
        return data[::-1]

    def bytes_to_binary(self, data):
        """
        将字节数据转换为二进制字符串

        Args:
            data: bytes对象

        Returns:
            str: 二进制字符串（例如：'00110101...'）
        """
        return ''.join(format(byte, '08b') for byte in data)

    def parse_register_data(self):
        """解析所有数据包中的寄存器数据"""
        for pkt_idx, data in enumerate(self.packets_data):
            for chip_id in range(self.NUM_CHIPS):
                chip_offset = chip_id * self.BYTES_PER_CHIP

                for reg_id in range(self.REGISTERS_PER_CHIP):
                    reg_offset = chip_offset + reg_id * self.BYTES_PER_REGISTER

                    # 提取4字节寄存器数据
                    reg_data_raw = data[reg_offset:reg_offset + self.BYTES_PER_REGISTER]

                    # 反转字节序
                    reg_data_reversed = self.reverse_bytes(reg_data_raw)

                    # 转换为二进制
                    binary_value = self.bytes_to_binary(reg_data_reversed)

                    # 存储该寄存器的值
                    key = (chip_id, reg_id)
                    self.register_values[key].append(binary_value)

    def compare_and_report(self):
        """比较所有数据包中相同芯片相同寄存器的值，并生成报告"""
        print("=" * 80)
        print("Register Value Analysis Report")
        print("=" * 80)

        all_identical = True
        inconsistent_regs = []

        for chip_id in range(self.NUM_CHIPS):
            for reg_id in range(self.REGISTERS_PER_CHIP):
                key = (chip_id, reg_id)
                values = self.register_values[key]

                # 获取唯一值
                unique_values = list(set(values))

                if len(unique_values) == 1:
                    # 所有值相同
                    print(f"CHIP{chip_id:2d} Reg{reg_id}  ✓  "
                          f"0x{int(unique_values[0], 2):08X}  "
                          f"{unique_values[0]}")
                else:
                    # 发现不一致
                    all_identical = False
                    inconsistent_regs.append((chip_id, reg_id))
                    print(f"CHIP{chip_id:2d} Reg{reg_id}  ✗  Inconsistent!")

                    # 统计每个值出现的次数
                    value_counts = {}
                    for val in values:
                        value_counts[val] = value_counts.get(val, 0) + 1

                    # 按出现次数排序
                    sorted_values = sorted(value_counts.items(),
                                         key=lambda x: x[1],
                                         reverse=True)

                    for idx, (val, count) in enumerate(sorted_values, 1):
                        packet_indices = [i+1 for i, v in enumerate(values) if v == val]
                        print(f"            Value{idx} ({count}x): "
                              f"0x{int(val, 2):08X}  {val}  "
                              f"Packets{packet_indices}")

        print("=" * 80)
        if all_identical:
            print("✓ All register values are consistent")
        else:
            print(f"✗ Found {len(inconsistent_regs)} inconsistent registers")
        print("=" * 80)

        return all_identical

    def run_analysis(self):
        """运行完整的分析流程"""
        # 提取数据包
        count = self.extract_packets()

        if count == 0:
            print(f"No packets of {self.TARGET_PACKET_LENGTH} bytes found")
            return

        # 解析寄存器数据
        print("Parsing register data...\n")
        self.parse_register_data()

        # 对比并生成报告
        self.compare_and_report()


def main():
    """主函数"""
    print("=" * 80)
    print("Iguana Chip Register Data Analysis Tool")
    print("=" * 80)

    # 检查命令行参数
    if len(sys.argv) < 2:
        print("\nUsage: python iguana_analyzer.py <PCAP_file_path>")
        print("\nExamples:")
        print("  python iguana_analyzer.py test_tool.pcap")
        print("  python iguana_analyzer.py C:\\Users\\FuYou\\Desktop\\data.pcap")
        sys.exit(1)

    pcap_file = sys.argv[1]

    # 创建分析器并运行
    analyzer = IguanaRegisterAnalyzer(pcap_file)
    analyzer.run_analysis()


if __name__ == "__main__":
    main()
