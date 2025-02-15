import argparse

import observer.observer as observer
import analyzer.analyzer as analyzer
import utils.conf as cf
import spoofer.spoofer as spoofer

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--role', type=str, help='role of the node: controller, observer or spoofer')
    parser.add_argument('--port', type=int, default=39999, help='port of the analyzer, observer, or spoofer')
    role = parser.parse_args().role
    port = parser.parse_args().port
    if role == 'controller':
        analyzer.main(port)
    elif role == 'observer':
        observer.main(port)
    elif role == 'spoofer':
        spoofer.main(port)