"""LANlord – entry point."""

from scanner.ui import LANlordApp


def main() -> None:
    app = LANlordApp()
    app.run()


if __name__ == "__main__":
    main()
