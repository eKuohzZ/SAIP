import argparse

import observer.observer as observer
import analyzer.analyzer as analyzer
import spoofer.spoofer as spoofer
import scanner.scanner as scanner

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--role', type=str, help='role of the node: controller, observer or spoofer')
    parser.add_argument('--port', type=int, default=39999, help='port of the analyzer, observer, or spoofer')
    parser.add_argument('--if_download', type=lambda x: (str(x).lower() == 'true'), 
                   default=True, help='if download data from s3')
    role = parser.parse_args().role
    port = parser.parse_args().port
    if_download = parser.parse_args().if_download
    if role == 'analyzer':
        vp = analyzer.Analyzer()
        vp.run(if_download)
    elif role == 'observer':
        vp = observer.Observer()
        vp.run(port)
    elif role == 'spoofer':
        vp = spoofer.Spoofer()
        vp.run(port)
    elif role == 'scanner':
        vp = scanner.Scanner()
        vp.run(port)