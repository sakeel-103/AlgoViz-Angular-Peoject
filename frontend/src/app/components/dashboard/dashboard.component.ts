import { Component, HostListener, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterModule, Router } from '@angular/router';
import { AuthService } from '../../services/auth.service';
import { ToastrService } from 'ngx-toastr';
import { FormsModule } from '@angular/forms';

@Component({
  selector: 'app-dashboard',
  standalone: true,
  imports: [CommonModule, RouterModule, FormsModule],
  templateUrl: './dashboard.component.html',
  styleUrls: ['./dashboard.component.css'],
})
export class DashboardComponent implements OnInit {
  isDropdownOpen = false;
  showChangeNameModal = false;
  showChangePasswordModal = false;
  showDeleteAccountModal = false;
  username: string = 'Guest';

  // Form models
  changeNameData = { newName: '' };
  changePasswordData = {
    currentPassword: '',
    newPassword: '',
    confirmPassword: '',
  };
  deleteAccountData = { password: '' };
  runVisualization: any;
  resetVisualization: any;

  constructor(
    private router: Router,
    private authService: AuthService,
    private toastr: ToastrService
  ) {}

  ngOnInit(): void {
    this.loadUserProfile();
  }

  loadUserProfile(): void {
    const user = this.authService.getCurrentUser();
    if (user && user.username) {
      this.username = user.username;
    } else {
      // If no user is found, redirect to login
      this.toastr.error('Please log in to access this page');
      this.router.navigate(['/login']);
    }
  }

  toggleDropdown(event: Event) {
    event.stopPropagation();
    this.isDropdownOpen = !this.isDropdownOpen;
  }

  @HostListener('document:click', ['$event'])
  closeDropdown(event: MouseEvent) {
    const targetElement = event.target as HTMLElement;
    if (!targetElement.closest('.profile-dropdown')) {
      this.isDropdownOpen = false;
    }
  }

  // Name Change Functions
  openChangeNameModal(): void {
    const user = this.authService.getCurrentUser();
    if (user) {
      this.changeNameData.newName = user.username || '';
      this.showChangeNameModal = true;
    } else {
      this.toastr.error('User session expired. Please log in again.');
      this.router.navigate(['/login']);
    }
  }

  submitChangeName(): void {
    if (!this.changeNameData.newName.trim()) {
      this.toastr.error('Please enter a valid name');
      return;
    }

    this.authService.updateName(this.changeNameData.newName).subscribe({
      next: (response) => {
        // Update local user data
        const user = this.authService.getCurrentUser();
        if (user) {
          user.username = this.changeNameData.newName;
          this.authService.setCurrentUser(user);
          this.username = this.changeNameData.newName;
        }
        this.toastr.success('Name updated successfully');
        this.showChangeNameModal = false;
      },
      error: (err) => {
        this.toastr.error(err.error?.message || 'Failed to update name');
      },
    });
  }

  // Password Change Functions
  openChangePasswordModal(): void {
    this.changePasswordData = {
      currentPassword: '',
      newPassword: '',
      confirmPassword: '',
    };
    this.showChangePasswordModal = true;
    // this.isDropdownOpen = false;
  }

  submitChangePassword(): void {
    if (
      this.changePasswordData.newPassword !==
      this.changePasswordData.confirmPassword
    ) {
      this.toastr.error('New password and confirmation do not match');
      return;
    }

    this.authService
      .changePassword(
        this.changePasswordData.currentPassword,
        this.changePasswordData.newPassword
      )
      .subscribe({
        next: () => {
          this.toastr.success('Password changed successfully');
          this.showChangePasswordModal = false;
          this.changePasswordData = {
            currentPassword: '',
            newPassword: '',
            confirmPassword: '',
          };
        },
        error: (err) => {
          this.toastr.error(err.error?.message || 'Failed to change password');
        },
      });
  }

  // Account Deletion Functions
  openDeleteAccountModal(): void {
    this.deleteAccountData = { password: '' };
    this.showDeleteAccountModal = true;
    this.isDropdownOpen = false;
  }

  submitDeleteAccount(): void {
    if (!this.deleteAccountData.password) {
      this.toastr.error('Please enter your password');
      return;
    }

    this.authService.deleteAccount(this.deleteAccountData.password).subscribe({
      next: () => {
        this.toastr.success('Account deleted successfully');
        this.router.navigate(['/login']);
      },
      error: (err) => {
        this.toastr.error(err.error?.message || 'Failed to delete account');
      },
    });
  }

  onLogout() {
    this.authService.clearUserData();
    this.toastr.success('Logged out successfully');
    this.router.navigate(['/login']);
  }
  // Close modal when clicking outside
  @HostListener('click', ['$event'])
  onClick(event: MouseEvent): void {
    const target = event.target as HTMLElement;
    if (target.classList.contains('modal-overlay')) {
      this.showChangeNameModal = false;
      this.showChangePasswordModal = false;
      this.showDeleteAccountModal = false;
    }
  }
}
