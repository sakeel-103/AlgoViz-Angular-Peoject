import { ComponentFixture, TestBed } from '@angular/core/testing';

import { PrimsAlgoComponent } from './prims-algo.component';

describe('PrimsAlgoComponent', () => {
  let component: PrimsAlgoComponent;
  let fixture: ComponentFixture<PrimsAlgoComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [PrimsAlgoComponent]
    })
    .compileComponents();

    fixture = TestBed.createComponent(PrimsAlgoComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
