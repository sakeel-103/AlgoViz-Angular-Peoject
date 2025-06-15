import { NgModule } from '@angular/core';
import { BrowserModule } from '@angular/platform-browser';
import { BrowserAnimationsModule } from '@angular/platform-browser/animations';
import { RouterModule, Routes } from '@angular/router';
import { ToastrModule } from 'ngx-toastr';
import { FormsModule, ReactiveFormsModule } from '@angular/forms';
import { provideAnimations } from '@angular/platform-browser/animations';
import { AppComponent } from './app.component';
import { ContactUsComponent } from './components/contact-us/contact-us.component';
import { PrimsAlgoComponent } from './components/prims-algo/prims-algo.component';
import { GraphCanvasWrapperComponent } from './components/prims-algo/graph-canvas-wrapper.component';
import { NavbarComponent } from './components/navbar/navbar.component';
import { DijkstraAlgoComponent } from './components/dijkstra-algo/dijkstra-algo.component';
import { WarshallAlgoComponent } from './components/warshall-algo/warshall-algo.component';
import { LoginPageComponent } from './components/login-page/login-page.component';
import { SignupComponent } from './components/signup-page/signup-page.component';

const routes: Routes = [
  { path: '', redirectTo: '/contact', pathMatch: 'full' },
  { path: 'contact', component: ContactUsComponent },
  { path: 'prims', component: PrimsAlgoComponent },
  { path: 'dijkstra', component: DijkstraAlgoComponent },
  { path: 'warshall', component: WarshallAlgoComponent },
];

@NgModule({
  declarations: [
    AppComponent,
    ContactUsComponent,
    LoginPageComponent,
    SignupComponent,
    NavbarComponent,
    PrimsAlgoComponent,
    DijkstraAlgoComponent,
    WarshallAlgoComponent,
    GraphCanvasWrapperComponent,
  ],
  imports: [
    BrowserModule,
    FormsModule,
    BrowserAnimationsModule,
    ReactiveFormsModule,
    RouterModule.forRoot(routes),
    ToastrModule.forRoot(),
  ],
  providers: [provideAnimations()],
  bootstrap: [AppComponent],
})
export class AppModule {}
