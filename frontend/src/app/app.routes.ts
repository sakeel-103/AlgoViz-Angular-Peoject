import { NgModule, Component } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';
// import { LoginPageComponent } from './components/login-page/login-page.component';
// import { SignupComponent } from './components/signup-page/signup-page.component';
import { HeaderComponent } from './components/header/header.component';
import { AboutUsComponent } from './components/aboutUs-page/aboutUs.component';
import { MainIndexComponent } from './components/main-index/main-index.component';
import { BfsPageComponent } from './components/bfs-page/bfs-page.component';
import { DfsPageComponent } from './components/dfs-page/dfs-page.component';
import { FaqComponent } from './components/faq/faq.component';
import { QuizComponent } from './components/quiz/quiz.component';
import { RealworldComponent } from './components/realworld/realworld.component';
import { QuestionBankComponent } from './components/practice/practice.component';
import { ResourcesComponent } from './components/resources/resources.component';
import { ContactUsComponent } from './components/contact-us/contact-us.component';
import { ReviewComponent } from './components/reviews/reviews.component';
import { NQueenVisualizerComponent } from './components/n-queen-visualizer/n-queen-visualizer.component';
import { ComparisonComponent } from './components/compare/compare.component';
import { PrimsAlgoComponent } from './components/prims-algo/prims-algo.component';
import { DijkstraAlgoComponent } from './components/dijkstra-algo/dijkstra-algo.component';
import { WarshallAlgoComponent } from './components/warshall-algo/warshall-algo.component';
import { DashboardComponent } from './components/dashboard/dashboard.component';

export const routes: Routes = [
  // {
  //   path: '',
  //   component: LoginPageComponent,
  // },
  {
    path: '',
    component: HeaderComponent,
  },
  // {
  //   path: 'signup',
  //   component: SignupComponent,
  // },
  {
    path: 'aboutUs',
    component: AboutUsComponent,
  },
  {
    path: 'contactUs',
    component: ContactUsComponent,
  },
  {
    path: 'mainIndex',
    component: MainIndexComponent,
  },
  {
    path: 'dfsPage',
    component: DfsPageComponent,
  },
  {
    path: 'bfsPage',
    component: BfsPageComponent,
  },
  {
    path: 'dashboard',
    component: DashboardComponent,
  },
  {
    path: 'faq',
    component: FaqComponent,
  },
  {
    path: 'prims-algo',
    component: PrimsAlgoComponent,
  },
  {
    path: 'dijkstras-algo',
    component: DijkstraAlgoComponent,
  },
  {
    path: 'warshall-algo',
    component: WarshallAlgoComponent,
  },
  {
    path: 'quiz',
    component: QuizComponent,
  },
  {
    path: 'real-world',
    component: RealworldComponent,
  },
  {
    path: 'questions',
    component: QuestionBankComponent,
  },
  {
    path: 'resources',
    component: ResourcesComponent,
  },
  {
    path: 'review',
    component: ReviewComponent,
  },
  {
    path: 'n-queen-visualizer',
    component: NQueenVisualizerComponent,
  },
  {
    path: 'compare',
    component: ComparisonComponent,
  },
  {
    path: '**',
    redirectTo: '',
  },
];

@NgModule({
  imports: [RouterModule.forRoot(routes)],
  exports: [RouterModule],
})
export class AppRoutingModule {}
