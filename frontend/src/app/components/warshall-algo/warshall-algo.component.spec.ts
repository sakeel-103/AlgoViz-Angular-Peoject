import { ComponentFixture, TestBed } from '@angular/core/testing';

import { WarshallAlgoComponent } from './warshall-algo.component';

describe('WarshallAlgoComponent', () => {
  let component: WarshallAlgoComponent;
  let fixture: ComponentFixture<WarshallAlgoComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [WarshallAlgoComponent]
    })
    .compileComponents();

    fixture = TestBed.createComponent(WarshallAlgoComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
