import { Injectable } from '@angular/core';
import { BehaviorSubject, Observable, throwError } from 'rxjs';
import { Router } from '@angular/router';
import { catchError, map, tap } from 'rxjs/operators';
import { environment } from '../../environments/environment';
import { HttpClient, HttpHeaders } from '@angular/common/http';

@Injectable({
  providedIn: 'root',
})
export class AuthService {
  private apiUrl = environment.BACKEND_API_URL;
  userList: any[] = [];
  addQuestion: any;
  addReply: any;

  // Add these new properties for user state management
  private currentUserSubject = new BehaviorSubject<any>(null);
  public currentUser = this.currentUserSubject.asObservable();

  constructor(private http: HttpClient, private router: Router) {
    // Initialize user from localStorage if available
    const user = localStorage.getItem('currentUser');
    if (user) {
      this.currentUserSubject.next(JSON.parse(user));
    }
  }

  /**
   * Sign up a new user
   * @param userData
   * @returns
   */
  signUp(userData: {
    username: string;
    email: string;
    password: string;
    confirmPassword: string;
  }): Observable<any> {
    const payload = {
      username: userData.username,
      email: userData.email,
      password: userData.password,
      confirmPassword: userData.confirmPassword,
    };

    console.log('Sending signup request:', payload);

    return this.http.post(`${this.apiUrl}/signup`, payload).pipe(
      tap((response) => {
        console.log('Sign-up successful:', response);
      }),
      catchError((error) => {
        console.error('Sign-up failed:', error);
        return throwError(() => error);
      })
    );
  }

  /**
   * Log in an existing user
   * @param userData
   * @returns
   */
  login(userData: { email: string; password: string }): Observable<any> {
    return this.http.post(`${this.apiUrl}/login`, userData).pipe(
      tap((response: any) => {
        if (response && response.success && response.token) {
          this.setCurrentUser({
            username: response.user.username,
            email: response.user.email,
            token: response.token,
          });
        }
      }),
      catchError((error) => {
        console.error('Login failed:', error);
        return throwError(() => error);
      })
    );
  }

  /**
   * Handle API Errors
   */
  private handleError(error: any): Observable<never> {
    let errorMessage = 'An unknown error occurred';

    if (error.error) {
      errorMessage = error.error.message || 'Signup failed. Try again.';
    }

    console.error('Error details:', error);
    return throwError(() => new Error(errorMessage));
  }

  /**
   * Login with Google (send the ID token to backend for verification)
   * @param idToken
   * @returns
   */
  loginWithGoogle(idToken: string): Observable<any> {
    const headers = new HttpHeaders({
      'Content-Type': 'application/json',
      Authorization: `Bearer ${idToken}`,
    });

    return this.http.post(
      `${this.apiUrl}/auth/google`,
      { token: idToken },
      { headers }
    );
  }

  /**
   * Reset user password
   * @param email
   * @param newPassword
   * @returns
   */
  resetPassword(email: string, newPassword: string): Observable<any> {
    const payload = {
      email: email,
      newPassword: newPassword,
    };

    return this.http.post(`${this.apiUrl}/reset-password`, payload).pipe(
      tap((response) => {
        console.log('Password reset successful:', response);
      }),
      catchError((error) => {
        console.error('Password reset error:', error);
        return throwError(() => error);
      })
    );
  }

  /**
   * Submit contact form
   * @param contactData
   * @returns
   */
  submitContactForm(formData: any): Observable<any> {
    return this.http.post(`${this.apiUrl}/contact`, formData).pipe(
      catchError((error) => {
        console.error('Service error:', error);
        // Transform error for easier handling
        if (error.error instanceof ErrorEvent) {
          // Client-side error
          throw {
            status: 0,
            message: 'Network error. Please check your connection.',
          };
        } else {
          // Server-side error
          throw {
            status: error.status,
            message: error.error?.message || 'Server error',
            errors: error.error?.errors,
          };
        }
      })
    );
  }

  /**
   * Get all users
   * @returns
   */
  getAllUsers(): Observable<any[]> {
    return this.http.get<any[]>(`${this.apiUrl}/users`);
  }

  /**
   * Log out the user
   */
  logout(): void {
    this.http.post(`${this.apiUrl}/logout`, {}).subscribe({
      next: () => {
        this.router.navigate(['/login']);
      },
      error: (error) => {
        console.error('Error logging out:', error);
      },
    });
  }

  /**
   * Fetch all users and store them in userList
   */
  // fetchAllUsers(): void {
  //   this.getAllUsers().subscribe({
  //     next: (res: any[]) => {
  //       this.userList = res;
  //     },
  //     error: (error) => {
  //       console.error('Error fetching users:', error);
  //     },
  //   });
  // }

  /* ============== NEW METHODS FOR PROFILE MANAGEMENT ================ */

  /**
   * Update user's name
   */
  // updateName(newName: string): Observable<any> {
  //   const headers = this.getAuthHeaders();

  //   return this.http
  //     .put(`${this.apiUrl}/update-name`, { newName }, { headers })
  //     .pipe(
  //       tap((response: any) => {
  //         // Update local user data
  //         const user = this.getCurrentUser();
  //         if (user) {
  //           user.username = newName;
  //           this.setCurrentUser(user);
  //         }
  //       }),
  //       catchError(this.handleError)
  //     );
  // }

  /**
   * Change user's password
   */
  // changePassword(
  //   currentPassword: string,
  //   newPassword: string
  // ): Observable<any> {
  //   const headers = this.getAuthHeaders();

  //   return this.http
  //     .put(
  //       `${this.apiUrl}/change-password`,
  //       { currentPassword, newPassword },
  //       { headers }
  //     )
  //     .pipe(catchError(this.handleError));
  // }

  /**
   * Delete user account
   */
  deleteAccount(password: string): Observable<any> {
    const headers = this.getAuthHeaders();

    // For DELETE with body
    return this.http
      .delete(`${this.apiUrl}/delete-account`, {
        headers: headers,
        body: { password },
      })
      .pipe(
        tap(() => {
          this.clearUserData();
        }),
        catchError(this.handleError)
      );
  }

  /* ============== HELPER METHODS ================ */

  /**
   * Get auth headers with token
   */
  // Add this to your AuthService
  // Add this method to your AuthService
  private getAuthHeaders(): HttpHeaders {
    const user = this.getCurrentUser();
    if (!user || !user.token) {
      this.router.navigate(['/login']);
      throw new Error('No user token available');
    }
    return new HttpHeaders({
      'Content-Type': 'application/json',
      Authorization: `Bearer ${user.token}`,
    });
  }

  // Update your methods to use these headers
  changePassword(
    currentPassword: string,
    newPassword: string
  ): Observable<any> {
    return this.http
      .put(
        `${this.apiUrl}/change-password`,
        { currentPassword, newPassword },
        { headers: this.getAuthHeaders() }
      )
      .pipe(
        catchError((error) => {
          console.error('Password change error:', error);
          return throwError(() => error);
        })
      );
  }

  // Update your methods to include headers
  updateName(newName: string): Observable<any> {
    return this.http
      .put(
        `${this.apiUrl}/update-name`,
        { newName },
        { headers: this.getAuthHeaders() }
      )
      .pipe(
        tap((response: any) => {
          const user = this.getCurrentUser();
          if (user) {
            user.username = newName;
            this.setCurrentUser(user);
          }
        })
      );
  }

  /**
   * Get authentication token from current user
   */
  private getAuthToken(): string {
    const user = this.getCurrentUser();
    return user?.token || '';
  }

  /**
   * Get current user data
   */
  getCurrentUser(): any {
    return this.currentUserSubject.value;
  }

  /**
   * Set current user data
   */
  setCurrentUser(user: any): void {
    // Ensure we store a standardized user object
    const userData = {
      username: user.username,
      email: user.email,
      token: user.token,
    };
    localStorage.setItem('currentUser', JSON.stringify(userData));
    this.currentUserSubject.next(userData);
  }

  /**
   * Clear all user data (for logout/account deletion)
   */
  clearUserData(): void {
    localStorage.removeItem('currentUser');
    this.currentUserSubject.next(null);
  }

  /**
   * Fetch all users and store them in userList
   */
  fetchAllUsers(): void {
    this.getAllUsers().subscribe({
      next: (res: any[]) => {
        this.userList = res;
      },
      error: (error) => {
        console.error('Error fetching users:', error);
      },
    });
  }
}
