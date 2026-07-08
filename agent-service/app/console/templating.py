"""Shared Jinja2 templates instance for the console."""
import os

from fastapi.templating import Jinja2Templates

_HERE = os.path.dirname(os.path.abspath(__file__))
templates = Jinja2Templates(directory=os.path.join(_HERE, "templates"))
