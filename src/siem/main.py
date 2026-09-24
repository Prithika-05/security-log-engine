from siem.ingestion.file_reader import read_log_file
from siem.parsing.log_parser import parse_log_line


def main() -> None:
    for line in read_log_file("data/sample.log"):
        entry = parse_log_line(line)
        print(entry)


if __name__ == "__main__":
    main()