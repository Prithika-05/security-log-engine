import argparse


def main() -> None:
    parser = argparse.ArgumentParser(description="Security log analytics engine")

    parser.add_argument(
        "--log-file",
        required=True,
        help="Path to the log file to process",
    )

    args = parser.parse_args()

    print(f"Processing: {args.log_file}")


if __name__ == "__main__":
    main()
