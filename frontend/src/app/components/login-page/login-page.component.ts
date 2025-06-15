import { Component, OnInit } from '@angular/core';
import { Router, RouterLink, RouterOutlet } from '@angular/router';
import { NgForm, FormsModule } from '@angular/forms';
import { CommonModule } from '@angular/common';
import { ToastrService } from 'ngx-toastr';
import { AuthService } from '../../services/auth.service';
import { environment } from '../../../environments/environment';

declare var gapi: any;

@Component({
  selector: 'app-login-page',
  standalone: true, // Ensure this is correct
  imports: [FormsModule, CommonModule, RouterLink],
  templateUrl: './login-page.component.html',
  styleUrls: ['./login-page.component.css'],
})
export class LoginPageComponent implements OnInit {
  showForgotPasswordModal = false;
  resetEmail = '';
  newPassword = '';
  confirmPassword = '';
  passwordVisible = false;
  email = '';
  password = '';
  remember = false;
  isDarkMode: any;

  constructor(
    private router: Router,
    private toastr: ToastrService,
    private authService: AuthService
  ) {}

  ngOnInit(): void {
    this.loadGoogleSignIn();
  }

  openForgotPasswordModal(): void {
    this.showForgotPasswordModal = true;
    const rememberedEmail = localStorage.getItem('rememberedEmail');
    if (rememberedEmail) {
      this.email = rememberedEmail;
      this.remember = true;
    }
  }

  closeForgotPasswordModal(): void {
    this.showForgotPasswordModal = false;
    this.resetEmail = '';
    this.newPassword = '';
    this.confirmPassword = '';
  }

  resetPassword(form: NgForm): void {
    if (!form.valid) {
      this.toastr.error('Please fill in all fields', 'Error');
      return;
    }

    if (this.newPassword !== this.confirmPassword) {
      this.toastr.error('Passwords do not match!', 'Error');
      return;
    }

    this.authService.resetPassword(this.resetEmail, this.newPassword).subscribe(
      () => {
        this.toastr.success('Password reset successfully!', 'Success');
        this.closeForgotPasswordModal();
      },
      () => {
        this.toastr.error('Failed to reset password', 'Error');
      }
    );
  }

  // Google Sign-In Methods
  loadGoogleSignIn(): void {
    if (typeof gapi !== 'undefined') {
      this.initializeGoogleAuth();
    } else {
      const script = document.createElement('script');
      script.src = 'https://apis.google.com/js/platform.js';
      script.async = true;
      script.defer = true;
      script.onload = () => {
        this.initializeGoogleAuth();
      };
      document.head.appendChild(script);
    }
  }

  // Update initializeGoogleAuth to use the new handler
  initializeGoogleAuth(): void {
    gapi.load('auth2', () => {
      const auth2 = gapi.auth2.init({
        client_id: environment.CLIENT_ID,
        cookiepolicy: 'single_host_origin',
      });

      const googleSignInButton = document.getElementById('google-signin-btn');
      if (googleSignInButton) {
        auth2.attachClickHandler(
          googleSignInButton,
          {},
          (googleUser: any) => {
            const id_token = googleUser.getAuthResponse().id_token;
            this.handleGoogleLogin(id_token);
          },
          () => {
            this.toastr.error('Google login failed', 'Error');
          }
        );
      } else {
        console.error('Google Sign-In button not found');
      }
    });
  }

  // Login Method
  login(form: NgForm): void {
    if (form.invalid) {
      this.toastr.error('Please fill in all fields', 'Error');
      return;
    }
    const { email, password, remember } = form.value;
    this.authService.login({ email, password }).subscribe({
      next: (response: any) => {
        if (remember) {
          localStorage.setItem('rememberedEmail', email);
        } else {
          localStorage.removeItem('rememberedEmail');
        }
        this.toastr.success('Login Successful', 'Success');
        this.router.navigate(['/header']);
      },
      error: (error) => {
        let errorMessage = 'Invalid email or password';
        if (error.error && error.error.message) {
          errorMessage = error.error.message;
        }
        this.toastr.error(errorMessage, 'Error');
      },
    });
  }

  // Enhanced Google login with user profile handling
  private handleGoogleLogin(id_token: string): void {
    this.authService.loginWithGoogle(id_token).subscribe({
      next: (response: any) => {
        // Store user data from Google login
        this.authService.setCurrentUser({
          username: response.name || response.email,
          email: response.email,
          token: response.token,
        });

        this.toastr.success('Google Login Successful', 'Success');
        this.router.navigate(['/dashboard']);
      },
      error: (error) => {
        this.toastr.error('Google login failed', 'Error');
        console.error('Google login error:', error);
      },
    });
  }

  // Toggle Password Visibility
  togglePasswordVisibility(): void {
    this.passwordVisible = !this.passwordVisible;
  }

  goBack(): void {
    this.router.navigate(['/signup']);
  }
}
