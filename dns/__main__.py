from threading import Thread

from dns.server import start


def main():
    global Alive
    Thread(target=start).start()
    while True:
        Alive = True
        while input() != 'q':
            continue
        Alive = False
        while input() != 's':
            continue


if __name__ == "__main__":
    main()
