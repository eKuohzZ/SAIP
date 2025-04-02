import argparse

import observer.observer as observer
import analyzer.analyzer as analyzer
import spoofer.spoofer as spoofer
import scanner.scanner as scanner

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--role', type=str, help='role of the node: controller, observer or spoofer')
    parser.add_argument('--port', type=int, default=39999, help='port of the analyzer, observer, or spoofer')
    role = parser.parse_args().role
    port = parser.parse_args().port
    if role == 'analyzer':
        vp = analyzer.Analyzer()
        vp.run()
    elif role == 'observer':
        vp = observer.Observer()
        vp.run(port)
    elif role == 'spoofer':
        vp = spoofer.Spoofer()
        vp.run(port)
    elif role == 'scanner':
        vp = scanner.Scanner()
        vp.run(port)