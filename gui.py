import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import password_generator
import password_storage

class PasswordManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Manager")
        self.root.geometry("800x500")
        self.root.resizable(True, True)
        
        self.password_manager = None
        self.setup_master_password()
        
        if self.password_manager is None:
            self.root.destroy()
            return
            
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
            
    def create_widgets(self):
        """Create all GUI widgets"""
        # Create notebook (tabbed interface)
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create main tabs
        self.passwords_tab = ttk.Frame(self.notebook)
        self.generator_tab = ttk.Frame(self.notebook)
        
        self.notebook.add(self.passwords_tab, text="Passwords")
        self.notebook.add(self.generator_tab, text="Password Generator")
        
        # Setup each tab
        self.setup_passwords_tab()
        self.setup_generator_tab()
        
    def setup_passwords_tab(self):
        """Set up the passwords tab"""
        # Frame for list and buttons
        list_frame = ttk.Frame(self.passwords_tab)
        list_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Password list
        ttk.Label(list_frame, text="Saved Passwords:").pack(anchor=tk.W)
        
        # Scrollable list
        self.password_listbox = tk.Listbox(list_frame, width=40, height=15)
        self.password_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.password_listbox.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.password_listbox.config(yscrollcommand=scrollbar.set)
        
        # Load the password list
        self.refresh_password_list()
        
        # Buttons for actions
        button_frame = ttk.Frame(self.passwords_tab)
        button_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=10, pady=10)
        
        ttk.Button(button_frame, text="Add Password", 
                  command=self.add_password).pack(fill=tk.X, pady=5)
        ttk.Button(button_frame, text="View Password", 
                  command=self.view_password).pack(fill=tk.X, pady=5)
        ttk.Button(button_frame, text="Delete Password", 
                  command=self.delete_password).pack(fill=tk.X, pady=5)
        ttk.Button(button_frame, text="Refresh List", 
                  command=self.refresh_password_list).pack(fill=tk.X, pady=5)
        
    def setup_generator_tab(self):
        """Set up the password generator tab"""
        # Configure layout
        frame = ttk.Frame(self.generator_tab, padding="10")
        frame.pack(fill=tk.BOTH, expand=True)
        
        # Length settings
        ttk.Label(frame, text="Password Length:").grid(column=0, row=0, sticky=tk.W, pady=5)
        self.length_var = tk.IntVar(value=12)
        length_spin = ttk.Spinbox(frame, from_=4, to=50, textvariable=self.length_var, width=5)
        length_spin.grid(column=1, row=0, sticky=tk.W, pady=5)
        
        # Character types
        ttk.Label(frame, text="Include:").grid(column=0, row=1, sticky=tk.W, pady=5)
        
        self.uppercase_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(frame, text="Uppercase letters", 
                       variable=self.uppercase_var).grid(column=0, row=2, sticky=tk.W, pady=2)
        
        self.lowercase_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(frame, text="Lowercase letters", 
                       variable=self.lowercase_var).grid(column=0, row=3, sticky=tk.W, pady=2)
        
        self.digits_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(frame, text="Digits", 
                       variable=self.digits_var).grid(column=0, row=4, sticky=tk.W, pady=2)
        
        self.special_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(frame, text="Special characters", 
                       variable=self.special_var).grid(column=0, row=5, sticky=tk.W, pady=2)
        
        # Generate button
        ttk.Button(frame, text="Generate Password", 
                  command=self.generate_password).grid(column=0, row=6, pady=10)
        
        # Result field
        ttk.Label(frame, text="Generated Password:").grid(column=0, row=7, sticky=tk.W, pady=5)
        
        self.password_var = tk.StringVar()
        password_entry = ttk.Entry(frame, textvariable=self.password_var, width=40)
        password_entry.grid(column=0, row=8, columnspan=2, sticky=tk.W, pady=5)
        
        # Copy and save buttons
        button_frame = ttk.Frame(frame)
        button_frame.grid(column=0, row=9, columnspan=2, sticky=tk.W, pady=10)
        
        ttk.Button(button_frame, text="Copy to Clipboard", 
                  command=self.copy_to_clipboard).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Save This Password", 
                  command=self.save_generated_password).pack(side=tk.LEFT, padx=5)
                  
    # --- Methods for passwords tab ---
    def refresh_password_list(self):
        """Refresh the passwords list"""
        self.password_listbox.delete(0, tk.END)
        websites = self.password_manager.get_all_websites()
        for website in sorted(websites):
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
        """View selected password"""
        selection = self.password_listbox.curselection()
        if not selection:
            messagebox.showwarning("Warning", "No website selected!")
            return
            
        website = self.password_listbox.get(selection[0])
        entry = self.password_manager.get_password(website)
        
        if entry:
            detail_window = tk.Toplevel(self.root)
            detail_window.title(f"Password: {website}")
            detail_window.geometry("400x200")
            detail_window.transient(self.root)
            
            ttk.Label(detail_window, text=f"Website: {website}").pack(anchor=tk.W, padx=20, pady=10)
            ttk.Label(detail_window, text=f"Username: {entry['username']}").pack(anchor=tk.W, padx=20, pady=5)
            
            # Password frame with show/hide option
            pass_frame = ttk.Frame(detail_window)
            pass_frame.pack(anchor=tk.W, fill=tk.X, padx=20, pady=5)
            
            ttk.Label(pass_frame, text="Password:").pack(side=tk.LEFT)
            password_var = tk.StringVar(value=entry['password'])
            password_entry = ttk.Entry(pass_frame, textvariable=password_var, show='*')
            password_entry.pack(side=tk.LEFT, padx=5)
            
            # Show/hide button
            show_var = tk.BooleanVar(value=False)
            
            def toggle_show_password():
                if show_var.get():
                    password_entry.config(show='')
                else:
                    password_entry.config(show='*')
                    
            ttk.Checkbutton(pass_frame, text="Show", variable=show_var, 
                           command=toggle_show_password).pack(side=tk.LEFT)
            
            # Copy button
            def copy_password():
                self.root.clipboard_clear()
                self.root.clipboard_append(entry['password'])
                messagebox.showinfo("Copied", "Password copied to clipboard!")
                
            ttk.Button(detail_window, text="Copy Password", 
                      command=copy_password).pack(anchor=tk.W, padx=20, pady=10)
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