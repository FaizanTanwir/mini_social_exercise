import sqlite3

def comment_reports():
    conn = sqlite3.connect("D:/University - Masters/Semester_1/P1_Social Computing/Lab/mini_social_exercise/database.sqlite")
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE comment_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            post_id INTEGER NOT NULL,
            reporter_id INTEGER NOT NULL
        );
    """)

    print("Table created.")

    conn.commit()
    conn.close()
    

comment_reports()