from app_config import db, app
from models import User

with app.app_context():
    db.create_all()
    print('All tables created....')





if __name__ == '__main__':
    app.run(debug=True)