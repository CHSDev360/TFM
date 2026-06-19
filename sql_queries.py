CREATE_FEEDBACK_TABLE = """
CREATE TABLE IF NOT EXISTS feedback (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nombre TEXT,
    valoracion INTEGER NOT NULL,
    comentario TEXT NOT NULL,
    fecha TEXT NOT NULL
)
"""

INSERT_FEEDBACK = """
INSERT INTO feedback (
    nombre,
    valoracion,
    comentario,
    fecha
)
VALUES (?, ?, ?, ?)
"""

SELECT_FEEDBACK = """
SELECT
    id,
    nombre,
    valoracion,
    comentario,
    fecha
FROM feedback
ORDER BY id DESC
"""

DELETE_FEEDBACK = """
DELETE FROM feedback
WHERE id = ?
"""