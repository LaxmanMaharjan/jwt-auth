from flask_script import Manager
from flask_migrate import Migrate, MigrateCommand

from server import app,db

migrate = Migrate(app, db)
manager = Manager(app)

manager.add_command('db', MigrateCommand)

# defining custom command line command
@manager.command
def create_db():
    """For creating db tables"""
    db.create_all()

@manager.command
def drop_db():
    """For Dropping db tables"""
    db.drop_all()

if __name__ == '__main__':
    manager.run()
