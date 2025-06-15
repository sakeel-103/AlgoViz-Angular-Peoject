import { Component } from '@angular/core';
import { Router } from '@angular/router';
import { ToastrService } from 'ngx-toastr';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { AuthService } from '../../services/auth.service';
import { CommonModule } from '@angular/common';
import { ReactiveFormsModule } from '@angular/forms';
import { RouterModule } from '@angular/router';

@Component({
  selector: 'app-signup-page',
  standalone: true,
  templateUrl: './signup-page.component.html',
  styleUrls: ['./signup-page.component.css'],
  imports: [CommonModule, ReactiveFormsModule, RouterModule],
})
export class SignupComponent {
  signupForm: FormGroup;
  passwordVisible: boolean = false;
  confirmPasswordVisible: boolean = false;
  isMenuOpen: boolean = false; // Add property to track menu visibility

  constructor(
    private fb: FormBuilder,
    private toastr: ToastrService,
    private authService: AuthService,
    private router: Router
  ) {
    this.signupForm = this.fb.group(
      {
        username: ['', [Validators.required, Validators.minLength(3)]],
        email: ['', [Validators.required, Validators.email]],
        password: ['', [Validators.required, Validators.minLength(6)]],
        confirmPassword: ['', [Validators.required]],
      },
      {
        validators: SignupComponent.passwordMatchValidator,
      }
    );
  }

  // Custom validator to check if passwords match
  static passwordMatchValidator(form: FormGroup) {
    const password = form.get('password')?.value;
    const confirmPassword = form.get('confirmPassword')?.value;
    return password === confirmPassword ? null : { mismatch: true };
  }

  // Toggle menu visibility
  toggleMenu() {
    this.isMenuOpen = !this.isMenuOpen;
  }

  // Handle form submission
  SignUp() {
    if (this.signupForm.invalid) {
      this.signupForm.markAllAsTouched();
      this.toastr.error(
        'Please fill out the form correctly.',
        'Validation Error'
      );
      return;
    }

    const signupData = {
      username: this.signupForm.value.username,
      email: this.signupForm.value.email,
      password: this.signupForm.value.password,
      confirmPassword: this.signupForm.value.confirmPassword,
    };

    this.authService.signUp(signupData).subscribe({
      next: (response) => this.handleSuccessfulSignup(response),
      error: (error) => this.handleSignupError(error),
    });
  }

  togglePasswordVisibility() {
    this.passwordVisible = !this.passwordVisible;
  }

  toggleConfirmPasswordVisibility() {
    this.confirmPasswordVisible = !this.confirmPasswordVisible;
  }

  openLogin() {
    this.router.navigate(['/login']);
  }

  goHome() {
    this.router.navigate(['/']);
  }

  get emailInvalid(): boolean {
    const emailControl = this.signupForm.get('email');
    return (emailControl?.invalid && emailControl?.touched) ?? false;
  }

  get passwordInvalid(): boolean {
    const passwordControl = this.signupForm.get('password');
    return (passwordControl?.invalid && passwordControl?.touched) ?? false;
  }

  get confirmPasswordInvalid(): boolean {
    const confirmPasswordControl = this.signupForm.get('confirmPassword');
    return (
      (confirmPasswordControl?.invalid && confirmPasswordControl?.touched) ??
      false
    );
  }

  get passwordsMismatch(): boolean {
    return (
      (this.signupForm.errors?.['mismatch'] &&
        this.signupForm.get('confirmPassword')?.touched) ??
      false
    );
  }

  private handleSuccessfulSignup(response: any): void {
    this.authService.setCurrentUser({
      username: this.signupForm.value.username,
      email: this.signupForm.value.email,
      token: response.token,
    });

    this.toastr.success('Sign-up successful! You can now log in.', 'Success');
    this.router.navigate(['/login']);
  }

  private handleSignupError(error: any): void {
    let errorMessage = 'Registration failed. Please try again.';

    if (error.error && error.error.message) {
      errorMessage = error.error.message;
    } else if (error.status === 409) {
      errorMessage = 'Email already exists. Please use a different email.';
    }

    this.toastr.error(errorMessage, 'Error');
    console.error('Sign-up error:', error);
  }
}
