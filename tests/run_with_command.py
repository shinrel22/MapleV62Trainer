from trainer.operator import HackingOperator


operator = HackingOperator()


def run():
    process_name = input('Enter your client name: ')
    process = operator.debugger.open_process(process_name)
    if not process:
        print('Cannot open %s' % process_name)
        return
    operator.h_process = operator.debugger.h_process

    while True:
        try:
            feature_name, active = input('Enter your cheat command: ')
        except ValueError:
            print('Invalid command format, must be "feature_name active"')
            continue

        if active == 'True':
            active = True

        elif active == 'False':
            active = False

        feature = getattr(operator, feature_name, None)
        if not feature:
            print('Feature %s not found.' % feature_name)
            continue

        feature(active)


if __name__ == '__main__':
    run()
