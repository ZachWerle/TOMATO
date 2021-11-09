def split_filepath(path):
    dirs = path.split('\\')
    return '\\'.join(dirs[0:-1]), dirs[-1]


def command_param_list(command):
    return [command.strip('\"').strip() for command in command.split(' ')]

