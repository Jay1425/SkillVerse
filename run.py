from app import create_app
from app.models import db

app = create_app()

if __name__ == '__main__':
    # Create all tables (only if not already created)
    with app.app_context():
        db.create_all()

    app.run(debug=True)
