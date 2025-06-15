import { Component, HostListener } from '@angular/core';

@Component({
  selector: 'app-navbar',
  standalone: true,
  templateUrl: './navbar.component.html',
  styleUrls: ['./navbar.component.css'],
})
export class NavbarComponent {
  isDropdownOpen = false;
  isMenuOpen = false;
  isVisualizationDropdownOpen = false;

  toggleDropdown() {
    this.isDropdownOpen = !this.isDropdownOpen;
  }

  toggleMenu() {
    this.isMenuOpen = !this.isMenuOpen;
    if (this.isMenuOpen) {
      this.isDropdownOpen = false;
      this.isVisualizationDropdownOpen = false;
    }
  }

  toggleVisualizationDropdown() {
    this.isVisualizationDropdownOpen = !this.isVisualizationDropdownOpen;
  }

  @HostListener('document:click', ['$event'])
  handleClickOutside(event: MouseEvent) {
    const targetElement = event.target as HTMLElement;

    // Handle profile dropdown
    const profileDropdown = document.querySelector(
      '.profile-dropdown .dropdown-content'
    );
    if (
      this.isDropdownOpen &&
      profileDropdown &&
      !profileDropdown.contains(targetElement) &&
      !targetElement.closest('.profile-dropdown')
    ) {
      this.isDropdownOpen = false;
    }

    // Handle visualization dropdown
    const visualizationDropdown = document.querySelector(
      '.dropdown .dropdown-content'
    );
    if (
      this.isVisualizationDropdownOpen &&
      visualizationDropdown &&
      !visualizationDropdown.contains(targetElement) &&
      !targetElement.closest('.dropdown')
    ) {
      this.isVisualizationDropdownOpen = false;
    }
  }

  onLogout() {
    console.log('User logged out');
  }
}
