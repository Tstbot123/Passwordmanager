"""Main des Passwordmanagers"""
from source.passwordManager import PasswordManager

def main() -> None:
    """Hauptfunktion, die den Passwortmanager ausführt."""
    manager: PasswordManager = PasswordManager()  # Typanmerkung für den Manager
    # Überprüfen, ob die Methode 'run' existiert und aufrufen
    if hasattr(manager, 'run') and callable(getattr(manager, 'run')):
        manager.run()  # Der Aufruf sollte jetzt keine Typfehler mehr verursachen
    else:
        print("Fehler: Die Methode 'run' existiert nicht in der Klasse 'PasswordManager'.")

if __name__ == "__main__":
    main()

