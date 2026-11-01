import { Module } from '@nestjs/common';
import { AiModule } from '../ai/ai.module';
import { ScanningModule } from '../scanning/scanning.module';
import { SourcesModule } from '../sources/sources.module';
import { PrScanExecutor } from './pr-scan.executor';
import { PrScansController } from './pr-scans.controller';
import { PrScansService } from './pr-scans.service';

/** Pull request scans requested from CI pipelines; results are posted back to the pull request. */
@Module({
  imports: [SourcesModule, ScanningModule, AiModule],
  controllers: [PrScansController],
  providers: [PrScansService, PrScanExecutor],
})
export class PrScansModule {}
