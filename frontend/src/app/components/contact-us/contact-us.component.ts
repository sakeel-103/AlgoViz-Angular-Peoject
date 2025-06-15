import { Component, Inject } from '@angular/core';
import { RouterModule } from '@angular/router';
import { ToastrService } from 'ngx-toastr';
import { OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { NavbarComponent } from '../navbar/navbar.component';

import {
  ReactiveFormsModule,
  FormBuilder,
  FormGroup,
  Validators,
} from '@angular/forms';
import { Router } from '@angular/router';
// Import CommonModule
import { AuthService } from '../../services/auth.service';

@Component({
  selector: 'app-contact-us',
  standalone: true,
  templateUrl: './contact-us.component.html',
  styleUrls: ['./contact-us.component.css'],
  imports: [
    RouterModule,
    ReactiveFormsModule,
    CommonModule,
    NavbarComponent,
    FormsModule,
  ], // Add CommonModule here
})
export class ContactUsComponent {
  contactForm: FormGroup;

  constructor(
    private fb: FormBuilder,
    private toastr: ToastrService,
    @Inject(AuthService) private contactService: AuthService,
    private router: Router
  ) {
    this.contactForm = this.fb.group({
      email: ['', [Validators.required, Validators.email]],
      question: ['', Validators.required],
      feedback: [''],
      suggestion: [''],
    });
  }

  onSubmit() {
    // Mark all fields as touched
    Object.values(this.contactForm.controls).forEach((control) => {
      control.markAsTouched();
    });

    if (this.contactForm.invalid) {
      this.toastr.error('Please correct the highlighted fields', 'Form Error');
      return;
    }

    const formData = {
      email: this.contactForm.value.email.trim(),
      question: this.contactForm.value.question.trim(),
      feedback: this.contactForm.value.feedback?.trim() || '',
      suggestion: this.contactForm.value.suggestion?.trim() || '',
    };

    this.contactService.submitContactForm(formData).subscribe({
      next: (res) => {
        this.toastr.success(
          'Your feedback was saved successfully!',
          'Thank You'
        );
        this.resetForm();
      },
      error: (err) => {
        console.error('Component error:', err);

        let message = 'Failed to submit form';
        if (err.status === 0) {
          message = 'Network error - please check your connection';
        } else if (err.errors) {
          message = Object.values(err.errors).join(', ');
        } else if (err.message) {
          message = err.message;
        }

        this.toastr.error(message, 'Error', { timeOut: 5000 });
      },
    });
  }

  // Helper method to mark all fields as touched
  private markFormGroupTouched(formGroup: FormGroup) {
    Object.values(formGroup.controls).forEach((control) => {
      control.markAsTouched();

      if (control instanceof FormGroup) {
        this.markFormGroupTouched(control);
      }
    });
  }

  resetForm() {
    this.contactForm.reset();
  }
  goBack(): void {
    window.history.back();
  }
}
