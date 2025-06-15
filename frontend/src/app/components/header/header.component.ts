import {
  Component,
  AfterViewInit,
  OnDestroy,
  HostListener,
} from '@angular/core';
import { RouterModule } from '@angular/router';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-header',
  standalone: true,
  imports: [RouterModule, CommonModule],
  templateUrl: './header.component.html',
  styleUrls: ['./header.component.css'],
})
export class HeaderComponent implements AfterViewInit, OnDestroy {
  private resizeListener: (() => void) | null = null;
  activeTab: string = 'dfs';
  showBFSGif: boolean = false;
  isBFSRunning: boolean = false;
  showDFSGif: boolean = false;
  isDFSRunning: boolean = false;
  showDijkstraGif: boolean = false;
  isDijkstraRunning: boolean = false;

  currentIndex: number = 0;
  // toggleDarkMode: any;
  // darkModeServices: any;
  isDarkMode: boolean = false;
  // toggleDropdown: any;
  isDropdownOpen: any;
  // onLogout: any;

  setActiveTab(tab: string) {
    this.activeTab = tab;
  }
  toggleDarkMode(): void {
    this.isDarkMode = !this.isDarkMode;

    if (this.isDarkMode) {
      document.body.classList.add('dark-mode');
    } else {
      document.body.classList.remove('dark-mode');
    }
    console.log('Dark Mode:', this.isDarkMode ? 'Enabled' : 'Disabled');
  }

  ngAfterViewInit() {
    const openNav = document.getElementById('menu-icon');
    const navLinks = document.getElementById('nav-links');

    if (openNav) {
      openNav.onclick = () => {
        openNav.classList.toggle('active-menu');
        if (navLinks) {
          navLinks.classList.toggle('active-navbar');
        }
      };
    }

    //  Event listener for resizing function
    this.resizeListener = this.handleResize.bind(this);
    window.addEventListener('resize', this.resizeListener);

    this.autoSlide(3000);
  }

  private handleResize() {
    const navLinks = document.getElementById('nav-links');
    if (window.innerWidth > 886 && navLinks) {
      navLinks.classList.remove('active-navbar');
    }
  }

  ngOnDestroy() {
    if (this.resizeListener) {
      window.removeEventListener('resize', this.resizeListener);
    }
  }

  // This is for BFS, DFS, Dijkstra visualization toggles functions which is implemented in the landing page
  startBFS() {
    this.isBFSRunning = !this.isBFSRunning;
    this.showBFSGif = this.isBFSRunning;
    console.log('BFS Started: ', this.showBFSGif);
  }

  startDFS() {
    this.isDFSRunning = !this.isDFSRunning;
    this.showDFSGif = this.isDFSRunning;
    console.log('DFS Started: ', this.showDFSGif);
  }

  startDijkstra() {
    this.isDijkstraRunning = !this.isDijkstraRunning;
    this.showDijkstraGif = this.isDijkstraRunning;
    console.log('Dijkstra Started: ', this.showDijkstraGif);
  }

  // For slides based on the index
  showSlide(index: number): void {
    const testimonialItems = document.querySelector(
      '.testimonial-items'
    ) as HTMLElement;
    const items = document.querySelectorAll('.testimonial-items .item');
    const totalItems = items.length;

    // It calculate the index for forward navigation cyclic only
    if (index >= totalItems) {
      this.currentIndex = 0;
    } else if (index < 0) {
      this.currentIndex = totalItems - 1;
    } else {
      this.currentIndex = index;
    }

    const offset = this.currentIndex * -100;
    testimonialItems.style.transform = `translateX(${offset}%)`;
  }

  // Function help to go to the next slide and it will be forward only
  nextSlide(): void {
    this.showSlide(this.currentIndex + 1);
  }

  autoSlide(interval: number): void {
    setInterval(() => {
      this.nextSlide();
    }, interval);
  }

  // Profile dropdown
  // isDropdownOpen = false;

  toggleDropdown() {
    this.isDropdownOpen = !this.isDropdownOpen;
  }

  @HostListener('document:click', ['$event'])
  handleClickOutside(event: MouseEvent) {
    const targetElement = event.target as HTMLElement;
    const dropdown = document.querySelector(
      '.profile-dropdown .dropdown-content'
    );

    // Check if the clicked element is outside the dropdown and the profile image
    if (
      this.isDropdownOpen &&
      dropdown &&
      !dropdown.contains(targetElement) &&
      !targetElement.closest('.profile-dropdown')
    ) {
      this.isDropdownOpen = false;
    }
  }

  onLogout() {
    // Implement logout logic here
    console.log('User logged out');
  }
}
