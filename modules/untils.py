import time 
import subprocess
from loguru import logger
import os 

def calculate_elapsed_time(start_time):
    elapsed_seconds = round(time.time() - start_time)

    m, s = divmod(elapsed_seconds, 60)
    h, m = divmod(m, 60)

    elapsed_time = []
    if h == 1:
        elapsed_time.append(str(h) + ' hour')
    elif h > 1:
        elapsed_time.append(str(h) + ' hours')

    if m == 1:
        elapsed_time.append(str(m) + ' minute')
    elif m > 1:
        elapsed_time.append(str(m) + ' minutes')

    if s == 1:
        elapsed_time.append(str(s) + ' second')
    elif s > 1:
        elapsed_time.append(str(s) + ' seconds')
    else:
        elapsed_time.append('less than a second')

    return ', '.join(elapsed_time)

def run_command(tools, command, output ):
    start_time = time.time()
    save = "echo %s | tee -a  %s" % (command,  output)
    subprocess.Popen(save , shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    p = subprocess.Popen(command , shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    logger.opt(colors=True).info("[i] Starting scan %s using command: <yellow>%s</yellow> ." % (tools, command))
    logger.opt(colors=True).info("<blue>[================================OUTPUT %s======================================]</blue>\n\n" % tools)
    for line in p.stdout.readlines():
        print(line.decode("utf8")),
    retval = p.wait()
    logger.opt(colors=True).info("<blue>[================================END OUTPUT %s======================================]</blue>\n\n" % tools )
    elapsed_time = calculate_elapsed_time(start_time)
    logger.opt(colors=True).info("<green>Task %s finished successfully in %s')</green>\n\n" %(command, elapsed_time))


def init_scan(directory_output):
    if not os.path.exists( directory_output):
        os.makedirs( directory_output)