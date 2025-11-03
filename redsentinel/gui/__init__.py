"""
RedSentinel GUI Module
Interface graphique moderne avec CustomTkinter
"""

from .main_window import RedSentinelGUI

__all__ = ['RedSentinelGUI']

def launch_gui():
    """Point d'entrée principal pour le GUI"""
    app = RedSentinelGUI()
    app.mainloop()

