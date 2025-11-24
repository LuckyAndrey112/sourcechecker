from time import sleep

from loguru import logger


def flask_logger():
    """creates logging information"""
    with open('logs/job.log') as log_info:
        for i in range(25):
            logger.info(f'iteration #{i}')
            data = log_info.read()
            yield data.encode()
            sleep(1)
        # Create empty job.log, old logging will be deleted
        open('logs/job.log', 'w').close()
