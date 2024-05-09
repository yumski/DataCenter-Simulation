import sys
from ryu.cmd import manager

def main():
    sys.argv.append('sdn_controller')
    sys.argv.append('--observe-links')
    # sys.argv.append('--verbose')
    sys.argv.append('--enable-debugger')
    # sys.argv.append('--log-file=ryu.log')
    manager.main()

if __name__ == '__main__':
    main()