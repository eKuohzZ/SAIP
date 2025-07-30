def build():
    ips = set()
    with open('/Users/hulahula_zk/Desktop/airSAIP/data/2025-05-29-tcp80.csv', 'r') as ifile:
        while True:
            lines = ifile.readlines(1000000)
            if not lines: break
            for line in lines:
                line = line.strip()
                ll = line.split(',')
                if len(ll) == 1: continue
                ips.add(ll[0])
    with open('/Users/hulahula_zk/Desktop/airSAIP/data/2025-05-29-tcp443.csv', 'r') as ifile:
        while True:
            lines = ifile.readlines(1000000)
            if not lines: break
            for line in lines:
                line = line.strip()
                ll = line.split(',')
                if len(ll) == 1: continue
                ips.add(ll[0])

    with open('/Users/hulahula_zk/Desktop/airSAIP/config/target6.csv', 'w') as ofile:
        for ip in ips:
            print(ip, file=ofile)

if __name__ == '__main__':
    build()