with open('/Users/hulahula_zk/Desktop/airSAIP/config/port_list.csv', 'w') as f:
    for i in range(36001, 36050):
        print(i, file=f)