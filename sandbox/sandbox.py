#!/usr/bin/env python3


def main():
    print("=" * 60)
    print("\tPython3 Sandbox - Run your python Code here ")
    print("\t\tHint: flag is flag.txt")
    print("=" * 60)

    while True:
        data = input('> ')

        for keyword in ['import', 'os', 'system', 'open', 'read', 'write', 'eval', 'exec', 'sh', 'bash']:
            if keyword in data.lower():
                print("Your are not allowed to input the key word!!!")
                return
        try:
            exec(data)
        except Exception as e:
            print(str(e))
            return


if __name__ == "__main__":
    main()
