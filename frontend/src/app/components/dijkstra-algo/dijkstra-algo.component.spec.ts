import { ComponentFixture, TestBed } from '@angular/core/testing';

import { DijkstraAlgoComponent } from './dijkstra-algo.component';

describe('DijkstraAlgoComponent', () => {
  let component: DijkstraAlgoComponent;
  let fixture: ComponentFixture<DijkstraAlgoComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [DijkstraAlgoComponent]
    })
    .compileComponents();

    fixture = TestBed.createComponent(DijkstraAlgoComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
