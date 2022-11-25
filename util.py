import numpy as np

def split_filepath(path):
    dirs = path.split('\\')
    return '\\'.join(dirs[0:-1]), dirs[-1]


def command_param_list(command):
    return [command.strip('\"').strip() for command in command.split(' ')]

def safe_divide(a: float, b: float):
    if b == 0:
        return 0
    
    return a / b

def aggregate_matrix(matrix):
    src_observ = np.sum(matrix['execution'], axis=0)
    dst_observ = np.sum(matrix['execution'], axis=1)

    return src_observ, dst_observ

def formalize_file(file_path):
    infile = open(file_path, "r")
    outfile = open("data/data.txt", "w")
    for line in infile.readlines():
        new_line = line.replace(":true", ":True")
        new_line = new_line.replace(":false", ":False")
        outfile.write(new_line)
    infile.close()
    outfile.close()
