import { Component, OnInit } from '@angular/core';
import { NavbarComponent } from '../navbar/navbar.component';
import { FormsModule } from '@angular/forms';
import { CommonModule } from '@angular/common';
import axios from 'axios';
import { ViewEncapsulation } from '@angular/core';
import { environment } from '../../../environments/environment';

interface Resource {
  title: string;
  link: string;
}

interface Video {
  title: string;
  link: string;
  thumbnail: string;
  category: string;
  author?: string;
  description?: string;
  publishedAt?: string;
}

const apiKey = 'AIzaSyBBnYSy5EKllIfdYEcL7WPdJuXkmCf7iCQ';

async function fetchYouTubeVideoDetails(
  videoId: string
): Promise<Partial<Video> | null> {
  try {
    const response = await axios.get(
      `https://www.googleapis.com/youtube/v3/videos`,
      {
        params: {
          part: 'snippet',
          id: videoId,
          key: apiKey,
        },
        timeout: 5000,
      }
    );

    if (!response.data.items || response.data.items.length === 0) {
      console.warn(`No video data found for video ID: ${videoId}`);
      return null;
    }

    const videoData = response.data.items[0].snippet;
    return {
      title: videoData.title,
      description: videoData.description,
      publishedAt: videoData.publishedAt,
      thumbnail:
        videoData.thumbnails?.high?.url ||
        videoData.thumbnails?.default?.url ||
        '',
      author: videoData.channelTitle || 'Unknown',
    };
  } catch (error: any) {
    const errorMessage = error.response?.data?.error?.message || error.message;
    const errorCode = error.response?.data?.error?.code || error.code;
    console.error(`Error fetching video details for video ID ${videoId}:`, {
      code: errorCode,
      message: errorMessage,
      reason: error.response?.data?.error?.errors?.[0]?.reason,
    });

    if (
      error.response?.status === 403 &&
      errorMessage.includes('quotaExceeded')
    ) {
      console.warn('YouTube API quota exceeded.');
      return null;
    } else if (error.response?.status === 400) {
      console.warn(`Invalid video ID or parameters: ${videoId}`);
      return null;
    } else if (axios.isAxiosError(error) && error.code === 'ECONNABORTED') {
      console.warn('API request timed out.');
      return null;
    }

    return null;
  }
}

@Component({
  selector: 'app-resources',
  standalone: true,
  imports: [FormsModule, NavbarComponent, CommonModule],
  templateUrl: './resources.component.html',
  styleUrls: ['./resources.component.css'],
  encapsulation: ViewEncapsulation.None,
})
export class ResourcesComponent implements OnInit {
  searchTerm: string = '';
  categories: string[] = ['All', 'Beginner', 'Intermediate', 'Advanced'];
  selectedCategory: string = 'All';
  selectedAuthor: string = '';
  videos: Video[] = [
    {
      title: '',
      link: 'https://www.youtube.com/watch?v=M3_pLsDdeuU',
      thumbnail: '',
      category: 'Beginner',
    },
    {
      title: '',
      link: 'https://www.youtube.com/watch?v=59fUtYYz7ZU',
      thumbnail: '',
      category: 'Intermediate',
    },
    {
      title: '',
      link: 'https://www.youtube.com/watch?v=TwdjOQMTaQ4',
      thumbnail: '',
      category: 'Advanced',
    },
    {
      title: '',
      link: 'https://www.youtube.com/watch?v=EaK6aslcC5g',
      thumbnail: '',
      category: 'Beginner',
    },
    {
      title: '',
      link: 'https://www.youtube.com/watch?v=gGlfzqPT-hE',
      thumbnail: '',
      category: 'Intermediate',
    },
    {
      title: '',
      link: 'https://www.youtube.com/watch?v=N2P7w22tN9c',
      thumbnail: '',
      category: 'Advanced',
    },
    {
      title: '',
      link: 'https://www.youtube.com/watch?v=pcKY4hjDrxk',
      thumbnail: '',
      category: 'Beginner',
    },
    {
      title: '',
      link: 'https://www.youtube.com/watch?v=Gc4mWrmJBsw',
      thumbnail: '',
      category: 'Beginner',
    },
    {
      title: '',
      link: 'https://www.youtube.com/watch?v=Gd92jSu_cZk',
      thumbnail: '',
      category: 'Beginner',
    },
    {
      title: '',
      link: 'https://www.youtube.com/watch?v=xFv_Hl4B83A',
      thumbnail: '',
      category: 'Beginner',
    },
    {
      title: '',
      link: 'https://www.youtube.com/watch?v=1jCFUv-Xlqo',
      thumbnail: '',
      category: 'Beginner',
    },
    {
      title: '',
      link: 'https://www.youtube.com/watch?v=SiI03wnREt4',
      thumbnail: '',
      category: 'Beginner',
    },
  ];

  resources: Resource[] = [
    {
      title: 'Graph Data Structure and Algorithms - GeeksforGeeks',
      link: 'https://www.geeksforgeeks.org/graph-data-structure-and-algorithms/',
    },
    {
      title: 'Graph Data Structure - WS Cube Tech',
      link: 'https://www.wscubetech.com/resources/dsa/graph-data-structure',
    },
    {
      title: 'Best Websites to Learn Heap and Graph Data Structures - Quora',
      link: 'https://www.quora.com/What-are-the-best-websites-to-learn-heap-and-graph-data-structures-with-practices',
    },
    {
      title: 'Introduction to Graphs - GeeksforGeeks',
      link: 'https://www.geeksforgeeks.org/introduction-to-graphs-data-structure-and-algorithm-tutorials/',
    },
    {
      title: 'Graphs in Data Structure - Simplilearn',
      link: 'https://www.simplilearn.com/tutorials/data-structure-tutorial/graphs-in-data-structure',
    },
    {
      title: 'Graph Algorithms - Tech Interview Handbook',
      link: 'https://www.techinterviewhandbook.org/algorithms/graph/',
    },
    {
      title: 'Top 13 Resources for Graph Theory and Algorithms - Neo4j',
      link: 'https://neo4j.com/blog/top-13-resources-graph-theory-algorithms/',
    },
    {
      title: 'How to Get Started with Data Structures - Reddit',
      link: 'https://www.reddit.com/r/learnprogramming/comments/ov7v91/how_do_i_get_started_with_data_structures_and/',
    },
  ];
  filteredVideos: Video[] = [];
  authors: string[] = [];
  errorMessage: string = '';
  apiError: boolean = false;

  async ngOnInit() {
    try {
      await this.fetchAllVideoDetails();
      this.populateAuthors();
      this.filteredVideos = [...this.videos];
    } catch (error) {
      console.error('Unexpected error in ngOnInit:', error);
      this.errorMessage = 'Failed to fetch videos. Please try again later.';
      this.apiError = true;
    }
  }

  async fetchAllVideoDetails() {
    let hasErrors = false;
    for (const video of this.videos) {
      const videoId = this.getVideoId(video.link);
      if (videoId) {
        const details = await fetchYouTubeVideoDetails(videoId);
        if (details) {
          video.title = details.title || video.title;
          video.thumbnail = details.thumbnail || video.thumbnail;
          video.author = details.author || 'Unknown';
        } else {
          hasErrors = true;
          video.title = `Graph Theory Video ${this.videos.indexOf(video) + 1}`;
          video.thumbnail = 'assets/images/fallback-thumbnail.jpg';
          console.warn(`Using fallback for video with ID: ${videoId}`);
        }
      } else {
        hasErrors = true;
        video.title = `Graph Theory Video ${this.videos.indexOf(video) + 1}`;
        video.thumbnail = 'assets/images/fallback-thumbnail.jpg';
        console.warn(`Invalid YouTube URL: ${video.link}`);
      }
    }
    if (hasErrors && this.videos.every((video) => !video.title)) {
      this.apiError = true;
      this.errorMessage = 'No videos could be fetched due to an API error.';
      console.error(
        'All video fetch attempts failed. Check API key, video IDs, or network.'
      );
    } else if (hasErrors) {
      this.errorMessage = 'Some videos could not be fetched.';
    }
  }

  populateAuthors() {
    this.authors = Array.from(
      new Set(
        this.videos
          .map((video) => video.author)
          .filter((author): author is string => author !== undefined)
      )
    );
  }

  filterByCategory(category: string) {
    this.selectedCategory = category;
    this.applyFilters();
  }

  filterByAuthor(author: string) {
    this.selectedAuthor = author;
    this.applyFilters();
  }

  applyFilters() {
    this.filteredVideos = this.videos.filter((video) => {
      const matchesCategory =
        this.selectedCategory === 'All' ||
        video.category === this.selectedCategory;
      const matchesAuthor =
        !this.selectedAuthor || video.author === this.selectedAuthor;
      const matchesSearch =
        this.searchTerm === '' ||
        video.title.toLowerCase().includes(this.searchTerm.toLowerCase());
      return matchesCategory && matchesAuthor && matchesSearch;
    });
  }

  getVideoId(link: string): string | null {
    const match = link.match(
      /(?:https?:\/\/)?(?:www\.)?youtube\.com\/watch\?v=([a-zA-Z0-9_-]{11})/
    );
    return match ? match[1] : null;
  }

  goToVideo(link: string) {
    window.open(link, '_blank');
  }

  goBack(): void {
    window.history.back();
  }
}
