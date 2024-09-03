import sys
import threading
import shutil


from lib import *
from constants import INFO_COLOR

class LoadingAnimation:
    def __init__(self):
        self.message_len:int = 0
        self.threading_stop_flag:threading.Event = threading.Event()
        self.animation_thread:threading.Thread = None
        
        self.total_count:int = 0
        self.current_count:int = 100
    
    def update_progress(self, current_count:int, total_count:int) -> None:
        self.current_count = current_count
        self.total_count = total_count
        
    def start(self, current_count:int, total_count:int) -> None:
        """
        Starts the loading animation in a separate thread.
        
        :param message: The message to display with the animation.
        :param animation_style: The type of animation (0 = None, 1 = Spinner, 2 = Dots).
        :param delay: The delay between each animation frame.
        """
        self.current_count = current_count
        self.total_count = total_count
        self.threading_stop_flag.clear()
        self.animation_thread = threading.Thread(target=self.loading_animation)
        self.animation_thread.start()
        
    
    def clear(self) -> None:
        """Clears the loading animation from the terminal."""
        sys.stdout.write("\033[999B")
        sys.stdout.write("\r" + " " * self.message_len + "\r")
        sys.stdout.write("\0338") 
        sys.stdout.flush()
        

    def stop(self) -> None:
        """Stops the loading animation."""
        self.threading_stop_flag.set()
        self.animation_thread.join()
        self.clear()
        
    def loading_animation(self) -> None:
        while not self.threading_stop_flag.is_set():
            self.render_animation_frame()
    

    
    
    def render_animation_frame(self) -> None:
        terminal_width, _ = shutil.get_terminal_size()
        self.message_len = terminal_width
        fixed_text_length = len(f" Progress: ({int((self.current_count / self.total_count) * 100)}%) [] ")
        
        bar_length = terminal_width - fixed_text_length
        
        if bar_length < 10:
            bar_length = 10
        
        progress = self.current_count / self.total_count
        blocks = int(bar_length * progress)
        bar = '#' * blocks + '-' * (bar_length - blocks)
        sys.stdout.write("\0337")  # Save cursor position
        sys.stdout.write("\0338")  # Restore cursor position
        sys.stdout.write("\033[999B")  # Move to bottom
        sys.stdout.write(f'\r{INFO_COLOR} Progress: ({int((self.current_count / self.total_count) * 100)}%) [{bar}] ')
        sys.stdout.write("\0338")  # Restore cursor position
        sys.stdout.flush()

        

           