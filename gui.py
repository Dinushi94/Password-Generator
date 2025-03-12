import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import password_generator
import password_storage
from functools import partial

class PasswordManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Manager")
        self.root.geometry("800x500")
        self.root.minsize(600, 400)
        
        self.password_manager = None
        
        # Initialize widget references before they're created
        self.password_listbox = None
        self.search_entry = None
        
        self.setup_master_password()
        
        if self.password_manager is None:
            self.root.destroy()
            return
            
        self.setup_style()
        self.create_widgets()
        
    def setup_master_password(self):
        """Set up or verify master password"""
        # Check if password file exists
        import os
        if os.path.exists("passwords.enc"):
            # Verify existing master password
            self.verify_master_password()
        else:
            # Create new master password
            self.create_master_password()
            
    def verify_master_password(self):
        """Verify existing master password"""
        password = simpledialog.askstring("Master Password", 
                                         "Enter your master password:", 
                                         show='*')
        if password is None:  # User clicked Cancel
            return
            
        # Create temporary manager to verify
        temp_manager = password_storage.PasswordManager(password)
        try:
            temp_manager.load_passwords()
            self.password_manager = temp_manager
        except Exception:
            messagebox.showerror("Error", "Incorrect master password!")
            self.verify_master_password()
            
    def create_master_password(self):
        """Create a new master password"""
        password = simpledialog.askstring("New Master Password", 
                                         "Create a master password:", 
                                         show='*')
        if password is None:  # User clicked Cancel
            return
            
        confirm = simpledialog.askstring("Confirm Password", 
                                        "Confirm your master password:", 
                                        show='*')
        if confirm is None:  # User clicked Cancel
            return
            
        if password != confirm:
            messagebox.showerror("Error", "Passwords do not match!")
            self.create_master_password()
            return
            
        self.password_manager = password_storage.PasswordManager(password)
        messagebox.showinfo("Success", "Master password created successfully!")
            
    def setup_style(self):
        """Apply modern theming"""
        self.style = ttk.Style()
        self.style.theme_use("clam")
        
        # Light theme
        self.style.configure(".", 
                            background="#f0f0f0", 
                            foreground="#000000",
                            fieldbackground="#ffffff")
        self.style.configure("TButton", 
                            font=("Arial", 12), 
                            padding=5)
        self.style.configure("TLabel", 
                            font=("Arial", 12), 
                            background="#f0f0f0")
        self.style.configure("TEntry", 
                            font=("Arial", 12))
        self.style.configure("TCheckbutton", 
                            background="#f0f0f0")
        self.style.configure("TFrame", 
                            background="#f0f0f0")
        self.style.map("TButton",
                      background=[('active', '#e0e0e0')])
        self.style.configure("TNotebook", 
                            background="#f0f0f0", 
                            tabmargins=[2, 5, 2, 0])
        self.style.configure("TNotebook.Tab", 
                            background="#e0e0e0", 
                            padding=[10, 2])
        self.style.map("TNotebook.Tab", 
                      background=[("selected", "#f0f0f0")])
    
    def create_widgets(self):
        """Create UI with enhancements"""
        # Main container
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Notebook for tabs
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.passwords_tab = ttk.Frame(self.notebook)
        self.generator_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.passwords_tab, text="Passwords")
        self.notebook.add(self.generator_tab, text="Generator")
        
        self.setup_passwords_tab()
        self.setup_generator_tab()
        
    def setup_passwords_tab(self):
        """Set up the passwords tab with grid layout"""
        # Main frame using grid
        main_frame = ttk.Frame(self.passwords_tab)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        main_frame.columnconfigure(0, weight=1)  # Search and list column
        main_frame.columnconfigure(1, weight=0)  # Buttons column
        main_frame.rowconfigure(1, weight=1)  # Listbox row
        
        # Search bar
        search_frame = ttk.Frame(main_frame)
        search_frame.grid(row=0, column=0, sticky="ew", pady=(0, 5))
        search_frame.columnconfigure(0, weight=1)
        
        ttk.Label(search_frame, text="Search:").grid(row=0, column=0, sticky="w")
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", self.filter_passwords)
        self.search_entry = tk.Entry(search_frame, textvariable=self.search_var, width=30)
        self.search_entry.grid(row=1, column=0, sticky="ew", pady=2)
        
        # Passwords list with scrollbar
        list_frame = ttk.Frame(main_frame)
        list_frame.grid(row=1, column=0, sticky="nsew")
        list_frame.rowconfigure(0, weight=1)
        list_frame.columnconfigure(0, weight=1)
        
        self.password_listbox = tk.Listbox(list_frame, font=("Arial", 12))
        self.password_listbox.grid(row=0, column=0, sticky="nsew")
        
        scrollbar_y = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.password_listbox.yview)
        scrollbar_y.grid(row=0, column=1, sticky="ns")
        
        scrollbar_x = ttk.Scrollbar(list_frame, orient=tk.HORIZONTAL, command=self.password_listbox.xview)
        scrollbar_x.grid(row=1, column=0, sticky="ew")
        
        self.password_listbox.config(yscrollcommand=scrollbar_y.set, xscrollcommand=scrollbar_x.set)
        
        # Setup right-click context menu
        self.context_menu = tk.Menu(self.password_listbox, tearoff=0)
        self.context_menu.add_command(label="View Password", command=self.view_password)
        self.context_menu.add_command(label="Copy Username", command=self.copy_username)
        self.context_menu.add_command(label="Copy Password", command=self.copy_password)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Delete Password", command=self.delete_password)
        
        self.password_listbox.bind("<Button-3>", self.show_context_menu)
        self.password_listbox.bind("<Double-Button-1>", lambda e: self.view_password())
        
        # Action buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=1, column=1, sticky="ns", padx=(10, 0))
        
        ttk.Button(button_frame, text="Add Password", 
                  command=self.add_password).pack(fill=tk.X, pady=5)
        ttk.Button(button_frame, text="View Password", 
                  command=self.view_password).pack(fill=tk.X, pady=5)
        ttk.Button(button_frame, text="Delete Password", 
                  command=self.delete_password).pack(fill=tk.X, pady=5)
        ttk.Button(button_frame, text="Refresh List", 
                  command=self.refresh_password_list).pack(fill=tk.X, pady=5)
        
        # Load passwords
        self.refresh_password_list()
    
    def show_context_menu(self, event):
        """Show context menu on right-click"""
        # Only show if an item is selected
        if self.password_listbox.curselection():
            self.context_menu.tk_popup(event.x_root, event.y_root)
    
    def copy_username(self):
        """Copy username to clipboard"""
        selection = self.password_listbox.curselection()
        if not selection:
            messagebox.showwarning("Warning", "No website selected!")
            return
            
        website = self.password_listbox.get(selection[0])
        entry = self.password_manager.get_password(website)
        
        if entry:
            self.root.clipboard_clear()
            self.root.clipboard_append(entry['username'])
            messagebox.showinfo("Copied", "Username copied to clipboard!")
    
    def copy_password(self):
        """Copy password to clipboard"""
        selection = self.password_listbox.curselection()
        if not selection:
            messagebox.showwarning("Warning", "No website selected!")
            return
            
        website = self.password_listbox.get(selection[0])
        entry = self.password_manager.get_password(website)
        
        if entry:
            self.root.clipboard_clear()
            self.root.clipboard_append(entry['password'])
            messagebox.showinfo("Copied", "Password copied to clipboard!")
            
    def filter_passwords(self, *args):
        """Filter passwords based on search string"""
        search_term = self.search_var.get().lower()
        self.password_listbox.delete(0, tk.END)
        
        websites = self.password_manager.get_all_websites()
        for website in sorted(websites):
            if search_term in website.lower():
                self.password_listbox.insert(tk.END, website)
        
    def setup_generator_tab(self):
        """Set up the password generator tab with grid layout"""
        # Main grid layout for generator tab
        frame = ttk.Frame(self.generator_tab, padding="10")
        frame.pack(fill=tk.BOTH, expand=True)
        
        # Configure the grid
        for i in range(4):
            frame.columnconfigure(i, weight=1)
        for i in range(10):
            frame.rowconfigure(i, weight=0)
        frame.rowconfigure(9, weight=1)  # Last row is expandable
        
        # Title
        ttk.Label(frame, text="Password Generator", font=("Arial", 14, "bold")).grid(
            column=0, row=0, columnspan=4, sticky="w", pady=(0, 10))
        
        # Length settings
        ttk.Label(frame, text="Password Length:").grid(column=0, row=1, sticky="w", pady=5)
        self.length_var = tk.IntVar(value=12)
        length_spin = ttk.Spinbox(frame, from_=4, to=50, textvariable=self.length_var, width=5)
        length_spin.grid(column=1, row=1, sticky="w", pady=5)
        
        # Character types
        ttk.Label(frame, text="Include:").grid(column=0, row=2, sticky="w", pady=5)
        
        self.uppercase_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(frame, text="Uppercase letters (A-Z)", 
                       variable=self.uppercase_var).grid(column=0, row=3, columnspan=2, sticky="w", pady=2)
        
        self.lowercase_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(frame, text="Lowercase letters (a-z)", 
                       variable=self.lowercase_var).grid(column=0, row=4, columnspan=2, sticky="w", pady=2)
        
        self.digits_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(frame, text="Digits (0-9)", 
                       variable=self.digits_var).grid(column=0, row=5, columnspan=2, sticky="w", pady=2)
        
        self.special_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(frame, text="Special characters (!@#$%^&*)", 
                       variable=self.special_var).grid(column=0, row=6, columnspan=2, sticky="w", pady=2)
        
        # Generate button
        gen_button = ttk.Button(frame, text="Generate Password", 
                               command=self.generate_password)
        gen_button.grid(column=0, row=7, columnspan=2, sticky="w", pady=10)
        
        # Result field
        ttk.Label(frame, text="Generated Password:").grid(column=0, row=8, sticky="w", pady=5)
        
        # Password display with toggle visibility button
        pass_frame = ttk.Frame(frame)
        pass_frame.grid(column=0, row=9, columnspan=4, sticky="ew", pady=5)
        
        self.password_var = tk.StringVar()
        self.show_password_var = tk.BooleanVar(value=False)
        
        self.password_entry = ttk.Entry(pass_frame, textvariable=self.password_var, width=40, show="*")
        self.password_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Toggle visibility button
        def toggle_password_visibility():
            if self.show_password_var.get():
                self.password_entry.config(show="")
            else:
                self.password_entry.config(show="*")
        
        eye_button = ttk.Button(pass_frame, text="👁", width=3, 
                               command=lambda: [self.show_password_var.set(not self.show_password_var.get()), 
                                               toggle_password_visibility()])
        eye_button.pack(side=tk.LEFT, padx=5)
        
        # Copy and save buttons
        button_frame = ttk.Frame(frame)
        button_frame.grid(column=0, row=10, columnspan=4, sticky="w", pady=10)
        
        ttk.Button(button_frame, text="Copy to Clipboard", 
                  command=self.copy_to_clipboard).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Save This Password", 
                  command=self.save_generated_password).pack(side=tk.LEFT, padx=5)
                  
    # --- Methods for passwords tab ---
    def refresh_password_list(self):
        """Refresh the passwords list"""
        # Store the search term
        search_term = self.search_var.get() if hasattr(self, 'search_var') else ""
        
        # Clear and reload the list
        self.password_listbox.delete(0, tk.END)
        websites = self.password_manager.get_all_websites()
        
        for website in sorted(websites):
            # Apply filter if search term exists
            if not search_term or search_term.lower() in website.lower():
                self.password_listbox.insert(tk.END, website)
            
    def add_password(self):
        """Add a new password"""
        website = simpledialog.askstring("Website", "Enter website name:")
        if not website:
            return
            
        username = simpledialog.askstring("Username", "Enter username:")
        if username is None:
            return
            
        password = simpledialog.askstring("Password", "Enter password:", show='*')
        if password is None:
            return
            
        self.password_manager.add_password(website, username, password)
        self.refresh_password_list()
        messagebox.showinfo("Success", f"Password for {website} saved!")
        
    def view_password(self):
        """View selected password with improved UI"""
        selection = self.password_listbox.curselection()
        if not selection:
            messagebox.showwarning("Warning", "No website selected!")
            return
            
        website = self.password_listbox.get(selection[0])
        entry = self.password_manager.get_password(website)
        
        if entry:
            detail_window = tk.Toplevel(self.root)
            detail_window.title(f"Password Details: {website}")
            detail_window.geometry("450x250")
            detail_window.transient(self.root)
            detail_window.grab_set()  # Make window modal
            
            # Apply theme to detail window
            detail_frame = ttk.Frame(detail_window, padding=20)
            detail_frame.pack(fill=tk.BOTH, expand=True)
            
            # Title
            ttk.Label(detail_frame, text=f"Password for {website}", 
                     font=("Arial", 14, "bold")).grid(column=0, row=0, columnspan=3, 
                                                    sticky="w", pady=(0, 15))
            
            # Username with copy button
            username_frame = ttk.Frame(detail_frame)
            username_frame.grid(column=0, row=1, columnspan=3, sticky="ew", pady=5)
            
            ttk.Label(username_frame, text="Username:").pack(side=tk.LEFT)
            username_entry = ttk.Entry(username_frame, width=30)
            username_entry.insert(0, entry['username'])
            username_entry.configure(state="readonly")
            username_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
            
            def copy_username_detail():
                detail_window.clipboard_clear()
                detail_window.clipboard_append(entry['username'])
                messagebox.showinfo("Copied", "Username copied to clipboard!")
                
            ttk.Button(username_frame, text="Copy", width=8, 
                      command=copy_username_detail).pack(side=tk.LEFT)
            
            # Password with show/hide and copy options
            pass_frame = ttk.Frame(detail_frame)
            pass_frame.grid(column=0, row=2, columnspan=3, sticky="ew", pady=5)
            
            ttk.Label(pass_frame, text="Password:").pack(side=tk.LEFT)
            
            password_var = tk.StringVar(value=entry['password'])
            password_entry = ttk.Entry(pass_frame, textvariable=password_var, show='*', width=30)
            password_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
            
            # Show/hide toggle with eye icon
            show_var = tk.BooleanVar(value=False)
            
            def toggle_show_password():
                if show_var.get():
                    password_entry.config(show='')
                else:
                    password_entry.config(show='*')
                    
            ttk.Button(pass_frame, text="👁", width=3, 
                      command=lambda: [show_var.set(not show_var.get()), toggle_show_password()]).pack(side=tk.LEFT)
            
            # Copy button
            def copy_password_detail():
                detail_window.clipboard_clear()
                detail_window.clipboard_append(entry['password'])
                messagebox.showinfo("Copied", "Password copied to clipboard!")
                
            ttk.Button(pass_frame, text="Copy", width=8, 
                      command=copy_password_detail).pack(side=tk.LEFT, padx=(5, 0))
            
            # Button row
            button_frame = ttk.Frame(detail_frame)
            button_frame.grid(column=0, row=3, columnspan=3, sticky="ew", pady=15)
            
            ttk.Button(button_frame, text="Close", 
                      command=detail_window.destroy).pack(side=tk.RIGHT)
        else:
            messagebox.showerror("Error", "Could not retrieve password!")
            
    def delete_password(self):
        """Delete selected password"""
        selection = self.password_listbox.curselection()
        if not selection:
            messagebox.showwarning("Warning", "No website selected!")
            return
            
        website = self.password_listbox.get(selection[0])
        confirm = messagebox.askyesno("Confirm", f"Delete password for {website}?")
        
        if confirm:
            success = self.password_manager.delete_password(website)
            if success:
                self.refresh_password_list()
                messagebox.showinfo("Success", f"Password for {website} deleted!")
            else:
                messagebox.showerror("Error", "Could not delete password!")
                
    # --- Methods for generator tab ---
    def generate_password(self):
        """Generate a new password"""
        try:
            # Validate at least one character type is selected
            if not any([self.uppercase_var.get(), self.lowercase_var.get(), 
                       self.digits_var.get(), self.special_var.get()]):
                messagebox.showerror("Error", "Select at least one character type!")
                return
                
            password = password_generator.generate_password(
                length=self.length_var.get(),
                use_uppercase=self.uppercase_var.get(),
                use_lowercase=self.lowercase_var.get(),
                use_digits=self.digits_var.get(),
                use_special_chars=self.special_var.get()
            )
            self.password_var.set(password)
        except ValueError as e:
            messagebox.showerror("Error", str(e))
            
    def copy_to_clipboard(self):
        """Copy password to clipboard"""
        password = self.password_var.get()
        if password:
            self.root.clipboard_clear()
            self.root.clipboard_append(password)
            messagebox.showinfo("Success", "Password copied to clipboard!")
        else:
            messagebox.showwarning("Warning", "No password to copy!")
            
    def save_generated_password(self):
        """Save the generated password"""
        password = self.password_var.get()
        if not password:
            messagebox.showwarning("Warning", "No password to save!")
            return
            
        website = simpledialog.askstring("Website", "Enter website name:")
        if not website:
            return
            
        username = simpledialog.askstring("Username", "Enter username:")
        if username is None:
            return
            
        self.password_manager.add_password(website, username, password)
        self.refresh_password_list()
        messagebox.showinfo("Success", f"Password for {website} saved!")


# Run the application
if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManagerApp(root)
    root.mainloop()