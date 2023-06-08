#!/usr/bin/env python3
import argparse
from select import select
from pcap import pcap
import yasca.all as yc


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--interface')
    parser.add_argument('-p', '--promisc', action='store_true')
    parser.add_argument('-v', '--verbose', action='store_true')
    parser.add_argument('filter', nargs=argparse.REMAINDER)
    args = parser.parse_args()

    _pcap = pcap(name=args.interface, promisc=args.promisc, timeout_ms=1)
    _pcap.setfilter(' '.join(args.filter))

    format_func = repr if args.verbose else str

    def cb(ts: float, pkt: bytes):
        print(format_func(yc.Ether.parse(pkt)))

    try:
        while True:
            rlist, _, _ = select([_pcap.fd], [], [], 1.0)
            if rlist:
                _pcap.dispatch(1, cb)
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()
