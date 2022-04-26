import psycopg2, logging, os
from data_processing import get_secret
from json import loads


logger = logging.getLogger(__name__)


# -- Configures, sends data to and retreives data from the database --

# Configure the database.ini file which separates the database connecting information allowing that file to be updated
# without changing the code in this file
def config() -> dict:
    host = os.environ.get('DATABASE_HOST')
    database = os.environ.get('DATABASE_NAME')
    user = os.environ.get('DATABASE_USER')
    password = loads(get_secret())['DATABASE_PASSWORD']

    db = {'host': host, 'database': database, 'user': user, 'password': password, 'port': 5432}

    return db


# Run SQL code
def run_SQL(run_this_code) -> None:
    connection = None

    try:
        return_error = None
        # The below line uses the previously defined config function to set params equal to the database.ini file
        params = config()
        logger.debug("Connecting to the PostgreSQL database...")
        # Connect to the DB
        connection = psycopg2.connect(**params)

        # Initiate cursor which allows the app to interact with the DB
        cursor = connection.cursor()
        logger.debug('Connection successful')

        # The cursor will run the code, passed to the function as an argument, below
        cursor.execute(f"{run_this_code}")
        connection.commit()
        logger.debug("Code executed")

        # Close connection to the cursor
        cursor.close()
        return return_error

    # The below will return the PostgreSQL error if there is one
    except (Exception, psycopg2.DatabaseError) as error:
        logger.error(error)
        return_error = error

    # Close the connection if it was made successfully
    finally:
        if connection is not None:
            connection.close()
            logger.debug('Database connection closed')
    return return_error


def fetch_SQL(run_this_code):
    connection = None
    output = None
    try:
        # The below line uses the previously defined config function to set params equal to the database.ini file
        params = config()
        logger.debug("Connecting to the PostgreSQL database...")
        # Connect to the DB
        connection = psycopg2.connect(**params)

        # Initiate cursor which allows the app to interact with the DB
        cursor = connection.cursor()
        logger.debug('Connection successful')

        # The cursor will run the code, passed to the function as an argument, below
        cursor.execute(f"{run_this_code}")
        output = cursor.fetchall()

        # Close connection to the cursor
        cursor.close()

    # The below will return the PostgreSQL error if there is one
    except (Exception, psycopg2.DatabaseError) as error:
        logger.error(error)

    # Close the connection if it was made successfully
    finally:
        if connection is not None:
            connection.close()
            logger.debug('Database connection closed')
    
    return output
